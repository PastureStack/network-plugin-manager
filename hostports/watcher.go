package hostports

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/docker/engine-api/client"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery              = 5 * time.Minute
	baseRuleRepairEvery       = 30 * time.Second
	hostPortsLabel            = "io.rancher.network.host_ports"
	hostPortsPostRoutingChain = "CATTLE_HOSTPORTS_POSTROUTING"
)

// Watch is used to monitor metadata for changes
func Watch(c metadata.Client, dc *client.Client) error {
	w := &watcher{
		c:  c,
		dc: dc,
		applied: ruleSet{
			Ports:          map[string]PortRule{},
			ForwardSubnets: map[string]string{},
		},
	}

	if err := setupKernelParameters(); err != nil {
		logrus.Errorf("error: %v", err)
	}

	go w.repairBaseRulesNoError()
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

type watcher struct {
	c           metadata.Client
	dc          *client.Client
	applied     ruleSet
	lastApplied time.Time
	baseRuleMu  sync.Mutex
	runCommand  func(args ...string) error
	output      func(args ...string) ([]byte, error)
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

	buf.WriteString(fmt.Sprintf("\n-A CATTLE_OUTPUT -p %v -m %v --dport %v -m addrtype --dst-type LOCAL -j DNAT --to-destination %v:%v",
		p.Protocol, p.Protocol, p.SourcePort, p.TargetIP, p.TargetPort))

	buf.WriteString(fmt.Sprintf("\n-A %s -s %v -d %v -p %v -m %v --dport %v -j MASQUERADE",
		hostPortsPostRoutingChain, p.TargetIP, p.TargetIP, p.Protocol, p.Protocol, p.TargetPort))

	return buf.Bytes()
}

func (w *watcher) insertBaseRules() error {
	var errs []string
	for _, iptables := range iptablesCommands("iptables") {
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
	}
	if len(errs) > 0 {
		return errors.Errorf("failed to insert hostport base rules: %s", strings.Join(errs, "; "))
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

	for {
		if err := w.run(iptables, "-w", "-D", "FORWARD", "-j", "CATTLE_FORWARD"); err != nil {
			break
		}
	}
	return w.run(iptables, "-w", "-I", "FORWARD", "1", "-j", "CATTLE_FORWARD")
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
	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to apply host rules: %v", err)
	}
}

func (w *watcher) repairBaseRulesNoError() {
	ticker := time.NewTicker(baseRuleRepairEvery)
	defer ticker.Stop()

	for range ticker.C {
		w.baseRuleMu.Lock()
		if err := w.insertBaseRules(); err != nil {
			logrus.Debugf("Ignoring hostport base rule repair error: %v", err)
		}
		w.baseRuleMu.Unlock()
	}
}

func (w *watcher) onChange(version string) error {
	logrus.Debug("Creating rule set")
	newRules := ruleSet{
		Ports:          map[string]PortRule{},
		ForwardSubnets: map[string]string{},
	}

	host, err := identity.LocalHost(w.c, w.dc)
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
				logrus.Warnf("Ignoring invalid host port definition for container %s (%s): %q", container.Name, container.ExternalId, port)
				continue
			}

			newRules.Ports[container.ExternalId+"/"+port] = rule
		}
	}

	logrus.Debugf("New generated rules: %v", newRules)
	if !reflect.DeepEqual(w.applied, newRules) {
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

	w.removeBaseRules()
	w.deleteOwnedChains()

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
	for _, rule := range rules.Ports {
		buf.WriteString("\n")
		buf.Write(rule.iptables())
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

	for _, restore := range iptablesCommands("iptables-restore") {
		cmd := exec.Command(restore, "-n")
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		cmd.Stdin = bytes.NewReader(buf.Bytes())
		if err := cmd.Run(); err != nil {
			logrus.Errorf("Failed to apply port rules with %s\n%s", restore, buf)
			return err
		}
	}

	if err := w.insertBaseRules(); err != nil {
		return errors.Wrap(err, "Applying port base iptables rules")
	}

	w.applied = rules
	w.lastApplied = time.Now()
	return nil
}

func (w *watcher) removeBaseRules() {
	commands := [][]string{
		{"-w", "-t", "nat", "-D", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_PREROUTING"},
		{"-w", "-t", "nat", "-D", "OUTPUT", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_OUTPUT"},
		{"-w", "-t", "nat", "-D", "POSTROUTING", "-j", hostPortsPostRoutingChain},
		{"-w", "-D", "FORWARD", "-j", "CATTLE_FORWARD"},
	}
	for _, iptables := range iptablesCommands("iptables") {
		for _, args := range commands {
			if err := w.run(append([]string{iptables}, args...)...); err != nil {
				logrus.Debugf("Ignoring hostport base rule removal error: %v", err)
			}
		}
	}
}

func (w *watcher) deleteOwnedChains() {
	chainsByTable := map[string][]string{
		"nat":    {"CATTLE_PREROUTING", "CATTLE_POSTROUTING", "CATTLE_OUTPUT", hostPortsPostRoutingChain},
		"filter": {"CATTLE_FORWARD"},
	}
	for table, chains := range chainsByTable {
		for _, chain := range chains {
			for _, iptables := range iptablesCommands("iptables") {
				if err := w.run(iptables, "-w", "-t", table, "-F", chain); err != nil {
					logrus.Debugf("Ignoring hostport chain flush error for %s/%s: %v", table, chain, err)
				}
				if err := w.run(iptables, "-w", "-t", table, "-X", chain); err != nil {
					logrus.Debugf("Ignoring hostport chain delete error for %s/%s: %v", table, chain, err)
				}
			}
		}
	}
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

	return PortRule{
		Bridge:     bridge,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		TargetIP:   targetIP,
		TargetPort: targetPort,
		Protocol:   proto,
	}, true
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
