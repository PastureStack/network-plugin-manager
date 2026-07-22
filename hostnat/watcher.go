package hostnat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"github.com/PastureStack/network-plugin-manager/conntracksync/conntrack"
	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/docker/engine-api/client"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery                = 5 * time.Minute
	staleIKEConntrackSweepEvery = 15 * time.Second
	natChain                    = "CATTLE_NAT_POSTROUTING"
)

// Watch is used to look for changes in metadata and apply hostnat related rules.
func Watch(c metadata.Client, dc *client.Client) error {
	w := &watcher{
		c:       c,
		dc:      dc,
		applied: ruleSet{},
	}
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

type watcher struct {
	c            metadata.Client
	dc           *client.Client
	applied      ruleSet
	lastApplied  time.Time
	lastIKESweep time.Time
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
	var errs []string
	for _, iptables := range iptablesCommands("iptables") {
		if w.run(iptables, "-w", "-t", "nat", "-C", "POSTROUTING", "-j", natChain) != nil {
			if err := w.run(iptables, "-w", "-t", "nat", "-I", "POSTROUTING", "-j", natChain); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return errors.Errorf("failed to insert hostnat base rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (w *watcher) run(args ...string) error {
	logrus.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (w *watcher) onChangeNoError(version string) {
	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to apply host rules: %v", err)
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
				return nil
			}
		}
	}

	return nil
}

func (w *watcher) apply(rules ruleSet) error {
	if err := w.enableLocalNetRouting(rules); err != nil {
		return err
	}

	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("*nat\n:%s -\n-F %s\n", natChain, natChain))
	for _, rule := range rules.IKE {
		buf.WriteString("\n")
		buf.Write(rule.iptables())
	}
	for _, rule := range rules.MASQ {
		buf.WriteString("\n")
		buf.Write(rule.iptables())
	}

	buf.WriteString("\nCOMMIT\n")

	if logrus.GetLevel() == logrus.DebugLevel {
		fmt.Printf("Applying rules\n%s", buf)
	}

	for _, restore := range iptablesCommands("iptables-restore") {
		cmd := exec.Command(restore, "-n")
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		cmd.Stdin = bytes.NewReader(buf.Bytes())
		if err := cmd.Run(); err != nil {
			logrus.Errorf("Failed to apply rules with %s\n%s", restore, buf)
			return err
		}
	}

	if err := w.insertBaseRules(); err != nil {
		return errors.Wrap(err, "Installing base rules")
	}

	if len(rules.IKE) > 0 {
		w.flushIKEConntrack()
		w.lastIKESweep = time.Now()
	}

	w.applied = rules
	w.lastApplied = time.Now()
	return nil
}

func iptablesCommands(name string) []string {
	commands := []string{name}
	legacyName := strings.Replace(name, "iptables", "iptables-legacy", 1)
	if legacyName == name {
		return commands
	}
	if _, err := exec.LookPath(legacyName); err != nil {
		return commands
	}
	if sameCommand(name, legacyName) {
		return commands
	}
	return append(commands, legacyName)
}

func sameCommand(a, b string) bool {
	aPath, aErr := exec.LookPath(a)
	bPath, bErr := exec.LookPath(b)
	if aErr != nil || bErr != nil {
		return false
	}
	aInfo, aErr := os.Stat(aPath)
	bInfo, bErr := os.Stat(bPath)
	if aErr != nil || bErr != nil {
		return false
	}
	return os.SameFile(aInfo, bInfo)
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
