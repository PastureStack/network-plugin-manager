package hostnat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/network-plugin-manager/conntracksync/conntrack"
	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	errNativeHookMismatch       = errors.New("owned postrouting nat hook is missing or changed")
	reapplyEvery                = 5 * time.Minute
	nativeCheckEvery            = 30 * time.Second
	staleIKEConntrackSweepEvery = 15 * time.Second
	natChain                    = "CATTLE_NAT_POSTROUTING"
)

// Watch is used to look for changes in metadata and apply hostnat related rules.
func Watch(c metadata.Client, dc *client.Client, backend firewall.Backend, report func(error)) error {
	w := &watcher{
		c:       c,
		dc:      dc,
		backend: backend,
		applied: ruleSet{},
		report:  report,
	}
	// /version may be ready before this container appears in metadata /services.
	// Keep the first reconcile asynchronous and let the metadata stream retry.
	go func() {
		w.onChangeNoError("initial")
		c.OnChange(5, w.onChangeNoError)
	}()
	if backend.Mode == firewall.NFTables {
		go w.watchNativeState()
	}
	return nil
}

type watcher struct {
	c            metadata.Client
	dc           *client.Client
	applied      ruleSet
	lastApplied  time.Time
	lastIKESweep time.Time
	backend      firewall.Backend
	restoreRules func(string, []byte, bool) error
	nftRules     func([]byte, bool) error
	nftState     func() ([]byte, error)
	runRules     func(...string) error
	report       func(error)
	reconcileMu  sync.Mutex
}

type ruleSet struct {
	MASQ map[string]MASQRule
	IKE  map[string]IKEPortSNATRule
}

// MASQRule is used to store the needed information for building
// a masquerading rule
type MASQRule struct {
	Subnet string
	Bridge string
}

type IKEPortSNATRule struct {
	SourceIP string
	HostIP   string
	Bridge   string
	Port     string
}

func (p MASQRule) iptables() []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("-A %s -p tcp -s %s ! -o %s -j MASQUERADE --to-ports 1024-65535\n", natChain, p.Subnet, p.Bridge))
	buf.WriteString(fmt.Sprintf("-A %s -p udp -s %s ! -o %s -j MASQUERADE --to-ports 1024-65535\n", natChain, p.Subnet, p.Bridge))
	buf.WriteString(fmt.Sprintf("-A %s -s %s ! -o %s -j MASQUERADE\n", natChain, p.Subnet, p.Bridge))

	// LOCAL src
	buf.WriteString(fmt.Sprintf("-A %s -o %s -m addrtype --src-type LOCAL --dst-type UNICAST -j MASQUERADE", natChain, p.Bridge))
	return buf.Bytes()
}

func (p MASQRule) localRoutingSetting() string {
	s := ""
	if p.Bridge != "" {
		s = fmt.Sprintf("net.ipv4.conf.%v.route_localnet=1", p.Bridge)
	}

	return s
}

func (p IKEPortSNATRule) iptables() []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("-A %s -p udp -m udp -s %s/32 --sport %s", natChain, p.SourceIP, p.Port))
	if p.Bridge != "" {
		buf.WriteString(" ! -o ")
		buf.WriteString(p.Bridge)
	}
	buf.WriteString(fmt.Sprintf(" -j SNAT --to-source %s:%s", p.HostIP, p.Port))
	return buf.Bytes()
}

func (w *watcher) insertBaseRules() error {
	iptables := w.backend.Command
	if iptables == "" {
		return fmt.Errorf("hostnat iptables command is not selected")
	}
	if w.run(iptables, "-w", "-t", "nat", "-C", "POSTROUTING", "-j", natChain) != nil {
		if err := w.run(iptables, "-w", "-t", "nat", "-I", "POSTROUTING", "-j", natChain); err != nil {
			return fmt.Errorf("install hostnat base jump: %w", err)
		}
	}
	return nil
}

func (w *watcher) run(args ...string) error {
	if w.runRules != nil {
		return w.runRules(args...)
	}
	logrus.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (w *watcher) onChangeNoError(version string) {
	for {
		w.reconcileMu.Lock()
		err := w.onChange(version)
		w.reportStatus(err)
		w.reconcileMu.Unlock()
		if err == nil {
			return
		}
		logrus.Errorf("Failed to apply host rules: %v", err)
		// The metadata version may remain unchanged after a transient failure.
		// Retry the current snapshot rather than waiting for another event.
		time.Sleep(5 * time.Second)
	}
}

func (w *watcher) reportStatus(err error) {
	if w.report != nil {
		w.report(err)
	}
}

// Metadata versions do not change when Docker or another actor removes our
// nft table. The ticker therefore checks only the platform-owned chain and
// reconciles without requiring a new metadata event. The same lock guards
// metadata callbacks, the last-applied snapshot and health reports.
func (w *watcher) watchNativeState() {
	ticker := time.NewTicker(nativeCheckEvery)
	defer ticker.Stop()
	for range ticker.C {
		w.reconcileNativeState()
	}
}

func (w *watcher) reconcileNativeState() {
	w.reconcileMu.Lock()
	defer w.reconcileMu.Unlock()
	if w.lastApplied.IsZero() {
		// The initial metadata reconciliation owns readiness and its 5s retry.
		return
	}
	if err := w.checkNativeState(); err != nil {
		w.reportStatus(fmt.Errorf("hostnat native nft state lost: %w", err))
		var applyErr error
		if errors.Is(err, errNativeHookMismatch) {
			// A plain add-chain is idempotent but cannot correct an existing
			// chain whose hook/priority was changed. Replace only our table in
			// one preflighted nft transaction; Docker's tables are untouched.
			applyErr = w.applyNFTReplacing(w.applied)
		} else {
			applyErr = w.apply(w.applied)
		}
		w.reportStatus(applyErr)
		if applyErr != nil {
			logrus.Errorf("Failed to restore hostnat native nft state: %v", applyErr)
		}
		return
	}
}

func (w *watcher) onChange(version string) error {
	logrus.Debug("Evaluating NAT host rules")
	newRules := ruleSet{
		MASQ: map[string]MASQRule{},
		IKE:  map[string]IKEPortSNATRule{},
	}

	host, err := identity.LocalHost(w.c, w.dc)
	if err != nil {
		return err
	}

	networks, err := w.c.GetNetworks()
	if err != nil {
		return err
	}
	networksByUUID := map[string]metadata.Network{}

	for _, network := range networks {
		networksByUUID[network.UUID] = network
		rule := w.networkToRule(network)
		if rule != nil {
			newRules.MASQ[network.UUID] = *rule
		}
	}

	if err := w.addIKESNATRules(host, networksByUUID, newRules.IKE); err != nil {
		return err
	}

	logrus.Debugf("New generated nat rules: %v", newRules)
	if !reflect.DeepEqual(w.applied, newRules) {
		logrus.Infof("Applying new nat rules")
		return w.apply(newRules)
	} else if time.Now().Sub(w.lastApplied) > reapplyEvery {
		return w.apply(newRules)
	}

	w.flushStaleIKEConntrack(newRules.IKE)

	logrus.Debugf("No change in applied nat rules")
	return nil
}

func (w *watcher) addIKESNATRules(host metadata.Host, networks map[string]metadata.Network, rules map[string]IKEPortSNATRule) error {
	if host.AgentIP == "" {
		logrus.Warnf("hostnat: local host %s has empty agent IP, skipping IKE SNAT rules", host.UUID)
		return nil
	}

	containers, err := w.c.GetContainers()
	if err != nil {
		return err
	}

	for _, container := range containers {
		if container.HostUUID != host.UUID ||
			!isIPsecOverlayContainer(container) ||
			container.PrimaryIp == "" ||
			(container.State != "running" && container.State != "starting") {
			continue
		}

		bridge := ""
		if network, ok := networks[container.NetworkUUID]; ok {
			bridge = bridgeForNetwork(network)
		}

		for _, port := range []string{"500", "4500"} {
			key := container.ExternalId + "/" + port
			rules[key] = IKEPortSNATRule{
				SourceIP: container.PrimaryIp,
				HostIP:   host.AgentIP,
				Bridge:   bridge,
				Port:     port,
			}
		}
	}

	return nil
}

func (w *watcher) networkToRule(network metadata.Network) *MASQRule {
	conf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	for _, file := range conf {
		props, _ := file.(map[string]interface{})
		hostNat, _ := props["hostNat"].(bool)
		cniType, _ := props["type"].(string)
		bridge, _ := props["bridge"].(string)
		bridgeSubnet, _ := props["bridgeSubnet"].(string)

		if hostNat && isBridgeCNIType(cniType) && bridge != "" && bridgeSubnet != "" {
			return &MASQRule{
				Subnet: bridgeSubnet,
				Bridge: bridge,
			}
		}
	}

	return nil
}

func bridgeForNetwork(network metadata.Network) string {
	conf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	for _, file := range conf {
		props, _ := file.(map[string]interface{})
		cniType, _ := props["type"].(string)
		bridge, _ := props["bridge"].(string)

		if isBridgeCNIType(cniType) && bridge != "" {
			return bridge
		}
	}

	return ""
}

func isBridgeCNIType(cniType string) bool {
	return cniType == "pasture-bridge" || cniType == "rancher-bridge"
}

func isIPsecOverlayContainer(container metadata.Container) bool {
	if container.Labels["io.pasturestack.component"] == "ipsec-overlay" {
		return true
	}
	return container.StackName == "ipsec" && container.ServiceName == "ipsec"
}

func (w *watcher) enableLocalNetRouting(rules ruleSet) error {
	for _, rule := range rules.MASQ {
		s := rule.localRoutingSetting()
		if s != "" {
			logrus.Debugf("s: %v", s)
			err := w.run("sysctl", "-w", s)
			if err != nil {
				logrus.Errorf("error enabling local net routing: %v", err)
				return err
			}
		}
	}

	return nil
}

func (w *watcher) apply(rules ruleSet) error {
	if err := validateNATRules(rules); err != nil {
		return err
	}
	if w.backend.Mode == firewall.NFTables {
		return w.applyNFT(rules)
	}
	if w.backend.Mode != firewall.IptablesNFT && w.backend.Mode != firewall.IptablesLegacy {
		return fmt.Errorf("hostnat firewall backend %q is not resolved", w.backend.Mode)
	}

	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("*nat\n:%s -\n-F %s\n", natChain, natChain))
	ikeKeys := make([]string, 0, len(rules.IKE))
	for key := range rules.IKE {
		ikeKeys = append(ikeKeys, key)
	}
	sort.Strings(ikeKeys)
	for _, key := range ikeKeys {
		buf.WriteString("\n")
		buf.Write(rules.IKE[key].iptables())
	}
	masqKeys := make([]string, 0, len(rules.MASQ))
	for key := range rules.MASQ {
		masqKeys = append(masqKeys, key)
	}
	sort.Strings(masqKeys)
	for _, key := range masqKeys {
		buf.WriteString("\n")
		buf.Write(rules.MASQ[key].iptables())
	}

	buf.WriteString("\nCOMMIT\n")

	if logrus.GetLevel() == logrus.DebugLevel {
		fmt.Printf("Applying rules\n%s", buf)
	}

	restore := w.backend.Restore
	if restore == "" {
		return fmt.Errorf("hostnat iptables restore command is not selected")
	}
	if err := w.restore(restore, buf.Bytes(), true); err != nil {
		return fmt.Errorf("hostnat restore preflight: %w", err)
	}
	if err := w.enableLocalNetRouting(rules); err != nil {
		return err
	}
	if err := w.restore(restore, buf.Bytes(), false); err != nil {
		return fmt.Errorf("hostnat restore: %w", err)
	}

	if err := w.insertBaseRules(); err != nil {
		return fmt.Errorf("install base rules: %w", err)
	}

	if len(rules.IKE) > 0 {
		w.flushIKEConntrack()
		w.lastIKESweep = time.Now()
	}

	w.applied = rules
	w.lastApplied = time.Now()
	return nil
}

func (w *watcher) restore(name string, data []byte, check bool) error {
	if w.restoreRules != nil {
		return w.restoreRules(name, data, check)
	}
	args := []string{"-n"}
	if check {
		args = append(args, "--test")
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

const nftNATTable = "pasturestack_hostnat"

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

// Metadata reaches a root network-management process. Reject malformed or
// executable nft/restore fragments before either backend changes live rules.
func validateNATRules(rules ruleSet) error {
	for key, rule := range rules.MASQ {
		prefix, err := netip.ParsePrefix(rule.Subnet)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return fmt.Errorf("hostnat MASQ %q has invalid IPv4 subnet %q", key, rule.Subnet)
		}
		if !interfaceName.MatchString(rule.Bridge) {
			return fmt.Errorf("hostnat MASQ %q has invalid bridge name %q", key, rule.Bridge)
		}
	}
	for key, rule := range rules.IKE {
		for name, value := range map[string]string{"source": rule.SourceIP, "host": rule.HostIP} {
			addr, err := netip.ParseAddr(value)
			if err != nil || !addr.Is4() {
				return fmt.Errorf("hostnat IKE %q has invalid %s IPv4 address %q", key, name, value)
			}
		}
		if rule.Bridge != "" && !interfaceName.MatchString(rule.Bridge) {
			return fmt.Errorf("hostnat IKE %q has invalid bridge name %q", key, rule.Bridge)
		}
		if !isIKEPort(rule.Port) {
			return fmt.Errorf("hostnat IKE %q has unsupported port %q", key, rule.Port)
		}
	}
	return nil
}

func nftNATScript(rules ruleSet) []byte {
	return nftNATScriptForTable(rules, nftNATTable)
}

func nftNATReplaceScript(rules ruleSet) []byte {
	return append([]byte("delete table ip "+nftNATTable+"\n"), nftNATScript(rules)...)
}

// The table parameter permits an isolated integration test to exercise the
// exact production batch against a temporary, test-owned table.
func nftNATScriptForTable(rules ruleSet, table string) []byte {
	buf := &bytes.Buffer{}
	// A platform-owned table is deliberately separate from Docker's tables.
	// Priority 99 precedes Docker's normal srcnat priority 100, so an existing
	// Docker masquerade rule cannot win before our overlay-specific SNAT.
	buf.WriteString("add table ip " + table + "\n")
	buf.WriteString("add chain ip " + table + " postrouting { type nat hook postrouting priority 99; policy accept; }\n")
	buf.WriteString("flush chain ip " + table + " postrouting\n")
	ikeKeys := make([]string, 0, len(rules.IKE))
	for key := range rules.IKE {
		ikeKeys = append(ikeKeys, key)
	}
	sort.Strings(ikeKeys)
	for _, key := range ikeKeys {
		rule := rules.IKE[key]
		fmt.Fprintf(buf, "add rule ip %s postrouting ip saddr %s udp sport %s", table, rule.SourceIP, rule.Port)
		if rule.Bridge != "" {
			fmt.Fprintf(buf, " oifname != \"%s\"", rule.Bridge)
		}
		fmt.Fprintf(buf, " snat to %s:%s\n", rule.HostIP, rule.Port)
	}
	masqKeys := make([]string, 0, len(rules.MASQ))
	for key := range rules.MASQ {
		masqKeys = append(masqKeys, key)
	}
	sort.Strings(masqKeys)
	for _, key := range masqKeys {
		rule := rules.MASQ[key]
		for _, protocol := range []string{"tcp", "udp"} {
			fmt.Fprintf(buf, "add rule ip %s postrouting ip saddr %s oifname != \"%s\" meta l4proto %s masquerade to :1024-65535\n", table, rule.Subnet, rule.Bridge, protocol)
		}
		fmt.Fprintf(buf, "add rule ip %s postrouting ip saddr %s oifname != \"%s\" masquerade\n", table, rule.Subnet, rule.Bridge)
		fmt.Fprintf(buf, "add rule ip %s postrouting oifname \"%s\" fib saddr type local fib daddr type unicast masquerade\n", table, rule.Bridge)
	}
	return buf.Bytes()
}

func (w *watcher) applyNFT(rules ruleSet) error {
	return w.applyNFTScript(rules, nftNATScript(rules))
}

func (w *watcher) applyNFTReplacing(rules ruleSet) error {
	if err := validateNATRules(rules); err != nil {
		return err
	}
	return w.applyNFTScript(rules, nftNATReplaceScript(rules))
}

func (w *watcher) applyNFTScript(rules ruleSet, script []byte) error {
	if err := w.nft(script, true); err != nil {
		return fmt.Errorf("hostnat nft preflight: %w", err)
	}
	if err := w.enableLocalNetRouting(rules); err != nil {
		return err
	}
	if err := w.nft(script, false); err != nil {
		return fmt.Errorf("hostnat nft apply: %w", err)
	}
	if len(rules.IKE) > 0 {
		w.flushIKEConntrack()
		w.lastIKESweep = time.Now()
	}
	w.applied = rules
	w.lastApplied = time.Now()
	return nil
}

func (w *watcher) nft(script []byte, check bool) error {
	if w.nftRules != nil {
		return w.nftRules(script, check)
	}
	args := []string{"-f", "-"}
	if check {
		args = append([]string{"-c"}, args...)
	}
	cmd := exec.Command(w.backend.Command, args...)
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func (w *watcher) checkNativeState() error {
	var data []byte
	var err error
	if w.nftState != nil {
		data, err = w.nftState()
	} else {
		data, err = exec.Command(w.backend.Command, "-j", "list", "chain", "ip", nftNATTable, "postrouting").CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("read owned chain: %w: %s", err, strings.TrimSpace(string(data)))
	}
	var state struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode owned chain: %w", err)
	}
	baseFound := false
	ruleCount := 0
	for _, entry := range state.Nftables {
		if raw, ok := entry["chain"]; ok {
			var chain struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Hook   string `json:"hook"`
				Prio   int    `json:"prio"`
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal(raw, &chain); err != nil {
				return fmt.Errorf("decode owned base chain: %w", err)
			}
			baseFound = chain.Family == "ip" && chain.Table == nftNATTable &&
				chain.Name == "postrouting" && chain.Type == "nat" &&
				chain.Hook == "postrouting" && chain.Prio == 99 && chain.Policy == "accept"
		}
		if raw, ok := entry["rule"]; ok {
			var rule struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Chain  string `json:"chain"`
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				return fmt.Errorf("decode owned rule: %w", err)
			}
			if rule.Family == "ip" && rule.Table == nftNATTable && rule.Chain == "postrouting" {
				ruleCount++
			}
		}
	}
	if !baseFound {
		return errNativeHookMismatch
	}
	wantRules := len(w.applied.IKE) + 4*len(w.applied.MASQ)
	if ruleCount != wantRules {
		return fmt.Errorf("owned postrouting rule count is %d, want %d", ruleCount, wantRules)
	}
	return nil
}

func (w *watcher) flushIKEConntrack() {
	for _, spec := range [][]string{
		{"conntrack", "-D", "-p", "udp", "--sport", "500"},
		{"conntrack", "-D", "-p", "udp", "--dport", "500"},
		{"conntrack", "-D", "-p", "udp", "--sport", "4500"},
		{"conntrack", "-D", "-p", "udp", "--dport", "4500"},
	} {
		if err := w.run(spec...); err != nil {
			logrus.Debugf("Ignoring IKE conntrack cleanup error: %v", err)
		}
	}
}

func (w *watcher) flushStaleIKEConntrack(rules map[string]IKEPortSNATRule) {
	if len(rules) == 0 || time.Since(w.lastIKESweep) < staleIKEConntrackSweepEvery {
		return
	}
	w.lastIKESweep = time.Now()

	entries, err := conntrack.ListSNAT()
	if err != nil {
		logrus.Debugf("Unable to list conntrack entries for IKE stale sweep: %v", err)
		return
	}

	for _, entry := range entries {
		rule, ok := matchingIKERule(entry, rules)
		if !ok || !staleIKEEntry(entry, rule) {
			continue
		}

		logrus.Infof("Deleting stale IKE conntrack entry: %+v", entry)
		if err := conntrack.CTEntryDelete(entry); err != nil {
			logrus.Debugf("Ignoring stale IKE conntrack delete error: %v", err)
		}
	}
}

func matchingIKERule(entry conntrack.CTEntry, rules map[string]IKEPortSNATRule) (IKEPortSNATRule, bool) {
	if entry.Protocol != "udp" {
		return IKEPortSNATRule{}, false
	}
	if !isIKEPort(entry.OriginalSourcePort) && !isIKEPort(entry.OriginalDestinationPort) &&
		!isIKEPort(entry.ReplySourcePort) && !isIKEPort(entry.ReplyDestinationPort) {
		return IKEPortSNATRule{}, false
	}

	for _, rule := range rules {
		if entry.OriginalSourceIP == rule.SourceIP ||
			entry.ReplySourceIP == rule.SourceIP ||
			entry.OriginalDestinationIP == rule.HostIP ||
			entry.ReplyDestinationIP == rule.HostIP {
			return rule, true
		}
	}
	return IKEPortSNATRule{}, false
}

func staleIKEEntry(entry conntrack.CTEntry, rule IKEPortSNATRule) bool {
	if entry.Unreplied {
		return true
	}

	if entry.OriginalSourceIP == rule.SourceIP && entry.ReplyDestinationIP != rule.HostIP {
		return true
	}

	return false
}

func isIKEPort(port string) bool {
	return port == "500" || port == "4500"
}
