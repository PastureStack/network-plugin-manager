package hostports

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery              = 5 * time.Minute
	baseRuleRepairEvery       = 30 * time.Second
	hostPortsLabel            = "io.rancher.network.host_ports"
	hostPortsPostRoutingChain = "CATTLE_HOSTPORTS_POSTROUTING"
)

// Watch is used to monitor metadata for changes
func Watch(c metadata.Client, dc *client.Client, backend firewall.Backend, report func(error)) error {
	w := &watcher{
		c:       c,
		dc:      dc,
		backend: backend,
		report:  report,
		applied: ruleSet{
			Ports:          map[string]PortRule{},
			ForwardSubnets: map[string]string{},
		},
	}

	// bridge-nf-call-iptables belongs to the xtables compatibility path.
	// Native Docker nftables has its own IP-family bridge hooks and does not
	// require the obsolete bridge sysctl (absent on a fresh Ubuntu 26.04 VM).
	if backend.Mode != firewall.NFTables {
		if err := setupKernelParameters(); err != nil {
			logrus.Warnf("bridge netfilter sysctl unavailable: %v", err)
		}
	}
	go w.repairBaseRulesNoError()
	go func() {
		w.onChangeNoError("initial")
		c.OnChange(5, w.onChangeNoError)
	}()
	return nil
}

type watcher struct {
	c            metadata.Client
	dc           *client.Client
	applied      ruleSet
	lastApplied  time.Time
	reconcileMu  sync.Mutex
	baseRuleMu   sync.Mutex
	backend      firewall.Backend
	runCommand   func(args ...string) error
	output       func(args ...string) ([]byte, error)
	restoreRules func(name string, args []string, data []byte) error
	report       func(error)
	localHost    func(metadata.Client, *client.Client) (metadata.Host, error)
}

type ruleSet struct {
	Ports          map[string]PortRule
	ForwardSubnets map[string]string
}

// PortRule is used to store the needed information for building a
// iptables rule
type PortRule struct {
	Bridge     string
	SourceIP   string
	SourcePort string
	TargetIP   string
	TargetPort string
	Protocol   string
}

func (p PortRule) prefix() []byte {
	buf := &bytes.Buffer{}
	buf.WriteString("-A CATTLE_PREROUTING")
	if p.Bridge != "" {
		buf.WriteString(" ! -i ")
		buf.WriteString(p.Bridge)
	}
	buf.WriteString(" -p ")
	buf.WriteString(p.Protocol)
	buf.WriteString(" -m ")
	buf.WriteString(p.Protocol)
	if p.SourceIP != "0.0.0.0" {
		buf.WriteString(" -d ")
		buf.WriteString(p.SourceIP)
	}
	buf.WriteString(" --dport ")
	buf.WriteString(p.SourcePort)
	return buf.Bytes()
}

func (p PortRule) iptables() []byte {
	// Rules like
	// -A CATTLE_PREROUTING -p ${protocol} --dport ${sourcePort} -j MARK --set-mark 4200
	// -A CATTLE_PREROUTING -p ${protocol} --dport ${sourcePort} -j DNAT --to ${targetIP}:${targetPort}
	// We use mark 4200.  It is important whatever mark we use that the 0x8000 and 0x4000 bits are unset.
	// Those bits are used by k8s and will conflict.
	buf := &bytes.Buffer{}
	buf.Write(p.prefix())
	buf.WriteString(" -j MARK --set-mark 4200\n")

	buf.Write(p.prefix())
	buf.WriteString(" -j DNAT --to ")
	buf.WriteString(p.TargetIP)
	buf.WriteString(":")
	buf.WriteString(p.TargetPort)

	if p.SourceIP == "0.0.0.0" {
		buf.WriteString(fmt.Sprintf("\n-A CATTLE_PREROUTING -p %v -m %v --dport %v -m addrtype --dst-type LOCAL -j DNAT --to-destination %v:%v",
			p.Protocol, p.Protocol, p.SourcePort, p.TargetIP, p.TargetPort))
	} else {
		buf.WriteString(fmt.Sprintf("\n-A CATTLE_PREROUTING -p %v -m %v --dport %v -d %v -j DNAT --to-destination %v:%v",
			p.Protocol, p.Protocol, p.SourcePort, p.SourceIP, p.TargetIP, p.TargetPort))
	}

	buf.WriteString(fmt.Sprintf("\n-A CATTLE_OUTPUT -p %v -m %v --dport %v -m addrtype --dst-type LOCAL",
		p.Protocol, p.Protocol, p.SourcePort))
	if p.SourceIP != "0.0.0.0" {
		buf.WriteString(" -d ")
		buf.WriteString(p.SourceIP)
	}
	buf.WriteString(fmt.Sprintf(" -j DNAT --to-destination %v:%v", p.TargetIP, p.TargetPort))

	buf.WriteString(fmt.Sprintf("\n-A %s -s %v -d %v -p %v -m %v --dport %v -j MASQUERADE",
		hostPortsPostRoutingChain, p.TargetIP, p.TargetIP, p.Protocol, p.Protocol, p.TargetPort))

	return buf.Bytes()
}

func (w *watcher) insertBaseRules() error {
	if w.backend.Mode == firewall.NFTables {
		return nil // Native nftables hooks live in our own base chains.
	}
	iptables := w.backend.Command
	if iptables == "" {
		return fmt.Errorf("hostports iptables command is not configured")
	}
	var errs []string
	if w.run(iptables, "-w", "-t", "nat", "-C", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_PREROUTING") != nil {
		if err := w.run(iptables, "-w", "-t", "nat", "-I", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_PREROUTING"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := w.ensureForwardJumpFirst(iptables); err != nil {
		errs = append(errs, err.Error())
	}
	if w.run(iptables, "-w", "-t", "nat", "-C", "OUTPUT", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_OUTPUT") != nil {
		if err := w.run(iptables, "-w", "-t", "nat", "-I", "OUTPUT", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_OUTPUT"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if w.run(iptables, "-w", "-t", "nat", "-C", "POSTROUTING", "-j", hostPortsPostRoutingChain) != nil {
		if err := w.run(iptables, "-w", "-t", "nat", "-I", "POSTROUTING", "-j", hostPortsPostRoutingChain); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to insert hostport base rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (w *watcher) run(args ...string) error {
	if w.runCommand != nil {
		return w.runCommand(args...)
	}
	logrus.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (w *watcher) commandOutput(args ...string) ([]byte, error) {
	if w.output != nil {
		return w.output(args...)
	}
	logrus.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func (w *watcher) ensureForwardJumpFirst(iptables string) error {
	out, err := w.commandOutput(iptables, "-w", "-S", "FORWARD")
	if err == nil && forwardJumpIsFirst(out) {
		return nil
	}
	// Install the new jump before removing stale copies. A failed insertion
	// must never leave a working FORWARD hook disconnected.
	if err := w.run(iptables, "-w", "-I", "FORWARD", "1", "-j", "CATTLE_FORWARD"); err != nil {
		return err
	}
	// An older jump may remain later in FORWARD. Leaving a single redundant
	// jump is safer than deleting by position while Docker may rewrite rules.
	// Subsequent repair sees the new first hook and does not add more copies.
	return nil
}

func forwardJumpIsFirst(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") {
			continue
		}
		return line == "-A FORWARD -j CATTLE_FORWARD"
	}
	return false
}

func (w *watcher) onChangeNoError(version string) {
	for {
		w.reconcileMu.Lock()
		err := w.onChangeLocked(version, false)
		w.reportLocked(err)
		w.reconcileMu.Unlock()
		if err == nil {
			return
		}
		logrus.Errorf("Failed to apply host rules: %v", err)
		// Retry even if the metadata version stays unchanged after failure.
		time.Sleep(5 * time.Second)
	}
}

func (w *watcher) repairBaseRulesNoError() {
	ticker := time.NewTicker(baseRuleRepairEvery)
	defer ticker.Stop()

	for range ticker.C {
		if err := w.repairOnce(); err != nil {
			logrus.Errorf("Failed to repair hostport rules: %v", err)
		}
	}
}

func (w *watcher) onChange(version string) error {
	w.reconcileMu.Lock()
	defer w.reconcileMu.Unlock()
	return w.onChangeLocked(version, false)
}

// repairOnce shares a lock with metadata callbacks so an older successful
// reconcile cannot overwrite a later failure (or vice versa) in readiness.
func (w *watcher) repairOnce() error {
	w.reconcileMu.Lock()
	defer w.reconcileMu.Unlock()

	force := false
	if w.backend.Mode == firewall.NFTables {
		if err := w.checkNFTRules(); err != nil {
			w.reportLocked(err)
			force = true
		}
	} else {
		w.baseRuleMu.Lock()
		err := w.insertBaseRules()
		w.baseRuleMu.Unlock()
		if err != nil {
			w.reportLocked(err)
			force = true
		}
	}
	err := w.onChangeLocked("periodic", force)
	w.reportLocked(err)
	return err
}

func (w *watcher) reportLocked(err error) {
	if w.report != nil {
		w.report(err)
	}
}

func (w *watcher) onChangeLocked(version string, force bool) error {
	logrus.Debug("Creating rule set")
	newRules := ruleSet{
		Ports:          map[string]PortRule{},
		ForwardSubnets: map[string]string{},
	}

	resolveHost := w.localHost
	if resolveHost == nil {
		resolveHost = identity.LocalHost
	}
	host, err := resolveHost(w.c, w.dc)
	if err != nil {
		return err
	}

	networks, err := networksByUUID(w.c)
	if err != nil {
		return err
	}
	for uuid, network := range networks {
		if subnet := forwardSubnetForNetwork(network); subnet != "" {
			newRules.ForwardSubnets[uuid] = subnet
		}
	}

	containers, err := w.c.GetContainers()
	if err != nil {
		return err
	}

	for _, container := range containers {
		network := networks[container.NetworkUUID]
		bridge := ""

		if container.State != "running" && container.State != "starting" {
			continue
		}

		if container.HostUUID != host.UUID ||
			!(network.HostPorts || (container.System && container.Labels[hostPortsLabel] == "true")) ||
			container.PrimaryIp == "" {
			continue
		}

		conf, _ := network.Metadata["cniConfig"].(map[string]interface{})
		for _, file := range conf {
			props, _ := file.(map[string]interface{})
			cniType, _ := props["type"].(string)
			checkBridge, _ := props["bridge"].(string)

			if isBridgeCNIType(cniType) && checkBridge != "" {
				bridge = checkBridge
			}
		}

		for _, port := range container.Ports {
			rule, ok := parsePortRule(bridge, host.AgentIP, container.PrimaryIp, port)
			if !ok {
				return fmt.Errorf("invalid host port definition for container %s (%s): %q", container.Name, container.ExternalId, port)
			}

			newRules.Ports[container.ExternalId+"/"+port] = rule
		}
	}

	logrus.Debugf("New generated rules: %v", newRules)
	if force || !reflect.DeepEqual(w.applied, newRules) {
		logrus.Infof("Applying new port rules")
		return w.apply(newRules)
	} else if time.Now().Sub(w.lastApplied) > reapplyEvery {
		return w.apply(newRules)
	}

	logrus.Debugf("No change in applied rules")
	return nil
}

func (w *watcher) apply(rules ruleSet) error {
	w.baseRuleMu.Lock()
	defer w.baseRuleMu.Unlock()
	if err := validateRuleSet(rules); err != nil {
		return err
	}
	if w.backend.Mode == firewall.NFTables {
		return w.applyNFT(rules)
	}
	if w.backend.Restore == "" {
		return fmt.Errorf("hostports restore command is not configured")
	}

	buf := &bytes.Buffer{}
	// NOTE: We don't use CATTLE_POSTROUTING, but for migration we just wipe it out
	buf.WriteString("*nat\n")
	buf.WriteString(":CATTLE_PREROUTING -\n")
	buf.WriteString(":CATTLE_POSTROUTING -\n")
	buf.WriteString(":CATTLE_OUTPUT -\n")
	buf.WriteString(fmt.Sprintf(":%s -\n", hostPortsPostRoutingChain))
	buf.WriteString("-F CATTLE_PREROUTING\n")
	buf.WriteString("-F CATTLE_POSTROUTING\n")
	buf.WriteString("-F CATTLE_OUTPUT\n")
	buf.WriteString(fmt.Sprintf("-F %s\n", hostPortsPostRoutingChain))
	portKeys := make([]string, 0, len(rules.Ports))
	for key := range rules.Ports {
		portKeys = append(portKeys, key)
	}
	sort.Strings(portKeys)
	for _, key := range portKeys {
		buf.WriteString("\n")
		buf.Write(rules.Ports[key].iptables())
	}

	buf.WriteString("\nCOMMIT\n\n*filter\n:CATTLE_FORWARD -\n")
	buf.WriteString("-F CATTLE_FORWARD\n")
	for _, subnet := range sortedForwardSubnets(rules.ForwardSubnets) {
		buf.WriteString(fmt.Sprintf("-A CATTLE_FORWARD -s %s -d %s -j ACCEPT\n", subnet, subnet))
	}
	buf.WriteString("-A CATTLE_FORWARD -m mark --mark 0x1068 -j ACCEPT\n")
	// For k8s
	buf.WriteString("-A CATTLE_FORWARD -m mark --mark 0x4000 -j ACCEPT\n")

	buf.WriteString("\nCOMMIT\n")

	if logrus.GetLevel() == logrus.DebugLevel {
		fmt.Printf("Applying rules\n%s", buf)
	}

	if err := w.restore(w.backend.Restore, []string{"--test", "-n"}, buf.Bytes()); err != nil {
		return fmt.Errorf("validate hostport rules: %w", err)
	}
	if err := w.restore(w.backend.Restore, []string{"-n"}, buf.Bytes()); err != nil {
		return fmt.Errorf("apply hostport rules: %w", err)
	}

	if err := w.insertBaseRules(); err != nil {
		return fmt.Errorf("apply port base iptables rules: %w", err)
	}

	w.applied = rules
	w.lastApplied = time.Now()
	return nil
}

func (w *watcher) restore(name string, args []string, data []byte) error {
	if w.restoreRules != nil {
		return w.restoreRules(name, args, data)
	}
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = bytes.NewReader(data)
	return cmd.Run()
}

func validateRuleSet(rules ruleSet) error {
	for _, rule := range rules.Ports {
		if err := validatePortRule(rule); err != nil {
			return err
		}
	}
	for _, subnet := range rules.ForwardSubnets {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return fmt.Errorf("invalid IPv4 forward subnet %q", subnet)
		}
	}
	return nil
}

func validatePortRule(rule PortRule) error {
	if rule.Bridge != "" {
		if len(rule.Bridge) > 15 {
			return fmt.Errorf("invalid bridge name %q", rule.Bridge)
		}
		for _, char := range rule.Bridge {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.') {
				return fmt.Errorf("invalid bridge name %q", rule.Bridge)
			}
		}
	}
	for _, address := range []string{rule.SourceIP, rule.TargetIP} {
		ip, err := netip.ParseAddr(address)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("invalid IPv4 hostport address %q", address)
		}
	}
	if !validPort(rule.SourcePort) || !validPort(rule.TargetPort) || (rule.Protocol != "tcp" && rule.Protocol != "udp") {
		return fmt.Errorf("invalid hostport protocol or port")
	}
	return nil
}

func parsePortRule(bridge, hostIP, targetIP, portDef string) (PortRule, bool) {
	proto := "tcp"
	parts := strings.Split(portDef, ":")
	if len(parts) != 3 {
		return PortRule{}, false
	}

	sourceIP, sourcePort, targetPort := parts[0], parts[1], parts[2]

	parts = strings.Split(targetPort, "/")
	if len(parts) == 2 {
		targetPort = parts[0]
		proto = parts[1]
	}
	if !validPort(sourcePort) || !validPort(targetPort) || (proto != "tcp" && proto != "udp") {
		return PortRule{}, false
	}

	rule := PortRule{
		Bridge:     bridge,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		TargetIP:   targetIP,
		TargetPort: targetPort,
		Protocol:   proto,
	}
	return rule, validatePortRule(rule) == nil
}

func validPort(port string) bool {
	if port == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func forwardSubnetForNetwork(network metadata.Network) string {
	conf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	for _, file := range conf {
		props, _ := file.(map[string]interface{})
		cniType, _ := props["type"].(string)
		bridgeSubnet, _ := props["bridgeSubnet"].(string)

		if isBridgeCNIType(cniType) && bridgeSubnet != "" {
			return bridgeSubnet
		}
	}

	return ""
}

func isBridgeCNIType(cniType string) bool {
	return cniType == "pasture-bridge" || cniType == "rancher-bridge"
}

func sortedForwardSubnets(subnetsByNetwork map[string]string) []string {
	seen := map[string]bool{}
	subnets := []string{}
	for _, subnet := range subnetsByNetwork {
		if subnet == "" || seen[subnet] {
			continue
		}
		seen[subnet] = true
		subnets = append(subnets, subnet)
	}
	sort.Strings(subnets)
	return subnets
}

func networksByUUID(c metadata.Client) (map[string]metadata.Network, error) {
	networkByUUID := map[string]metadata.Network{}
	networks, err := c.GetNetworks()
	if err != nil {
		return nil, err
	}

	for _, network := range networks {
		networkByUUID[network.UUID] = network
	}

	return networkByUUID, nil
}

func setupKernelParameters() error {
	cmd := exec.Command("sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logrus.Errorf("error setting up kernel parameters")
		return err
	}
	return nil
}
