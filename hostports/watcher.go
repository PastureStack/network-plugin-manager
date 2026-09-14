package hostports

import (
	"bytes"
	"context"
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
	"github.com/PastureStack/network-plugin-manager/internal/hostlabel"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	reapplyEvery              = 5 * time.Minute
	baseRuleRepairEvery       = 30 * time.Second
	hostPortsLabel            = "io.rancher.network.host_ports"
	hostPortsPostRoutingChain = "CATTLE_HOSTPORTS_POSTROUTING"
	hostPortsRawChain         = "CATTLE_HOSTPORTS_RAW"
)

// Watch is used to monitor metadata for changes
func Watch(c metadata.Client, dc *client.Client, backend firewall.Backend, report func(error)) error {
	routeLocalnetOriginal, err := loadRouteLocalnetState(routeLocalnetStatePath)
	if err != nil {
		return fmt.Errorf("load route_localnet ownership: %w", err)
	}
	previousRouteLocalnet := map[string]bool{}
	for bridge := range routeLocalnetOriginal {
		previousRouteLocalnet[bridge] = true
	}
	w := &watcher{
		c:                      c,
		dc:                     dc,
		backend:                backend,
		report:                 report,
		getRouteLocalnet:       readBridgeRouteLocalnet,
		setRouteLocalnet:       setBridgeRouteLocalnet,
		routeLocalnetOriginal:  routeLocalnetOriginal,
		routeLocalnetStatePath: routeLocalnetStatePath,
		applied: ruleSet{
			Ports:                map[string]PortRule{},
			ForwardSubnets:       map[string]string{},
			ForwardBridges:       map[string]string{},
			RouteLocalnetBridges: previousRouteLocalnet,
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
	c                      metadata.Client
	dc                     *client.Client
	applied                ruleSet
	lastApplied            time.Time
	reconcileMu            sync.Mutex
	baseRuleMu             sync.Mutex
	backend                firewall.Backend
	runCommand             func(args ...string) error
	output                 func(args ...string) ([]byte, error)
	restoreRules           func(name string, args []string, data []byte) error
	getRouteLocalnet       func(bridge string) (bool, error)
	setRouteLocalnet       func(bridge string, enabled bool) error
	routeLocalnetOriginal  map[string]bool
	routeLocalnetStatePath string
	report                 func(error)
	localHost              func(metadata.Client, *client.Client) (metadata.Host, error)
	containerIPv4          func(containerID, subnet string) (string, error)
	containerPID           func(containerID string) (int, error)
	namespaceIPv4          func(pid int) ([]netlink.Addr, error)
}

type ruleSet struct {
	Ports                map[string]PortRule
	ForwardSubnets       map[string]string
	ForwardBridges       map[string]string
	ForwardPeers         map[string][]string
	SharedIngress        map[string]bool
	RouteLocalnetBridges map[string]bool
}

// PortRule is used to store the needed information for building a
// iptables rule
type PortRule struct {
	Bridge         string
	SourceIP       string
	SourcePort     string
	TargetIP       string
	TargetPort     string
	Protocol       string
	MasqueradeDNAT bool
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

	// Locally originated traffic has no ingress bridge and must not reach a
	// workload with a loopback or host source address. A flat L2 workload has
	// an external default gateway, so every owned DNAT flow must instead return
	// through this host's conntrack entry. Keep both rules scoped to this exact
	// published target; unrelated forwarding and DNAT rules remain untouched.
	if p.MasqueradeDNAT {
		buf.WriteString(fmt.Sprintf("\n-A %s -m conntrack --ctstate DNAT -d %v -p %v -m %v --dport %v -j MASQUERADE",
			hostPortsPostRoutingChain, p.TargetIP, p.Protocol, p.Protocol, p.TargetPort))
	} else {
		buf.WriteString(fmt.Sprintf("\n-A %s -m conntrack --ctstate DNAT -m addrtype --src-type LOCAL -d %v -p %v -m %v --dport %v -j MASQUERADE",
			hostPortsPostRoutingChain, p.TargetIP, p.Protocol, p.Protocol, p.TargetPort))
	}

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
	if w.run(iptables, "-w", "-t", "raw", "-C", "PREROUTING", "-j", hostPortsRawChain) != nil {
		if err := w.run(iptables, "-w", "-t", "raw", "-I", "PREROUTING", "1", "-j", hostPortsRawChain); err != nil {
			errs = append(errs, err.Error())
		}
	}
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
		Ports:                map[string]PortRule{},
		ForwardSubnets:       map[string]string{},
		ForwardBridges:       map[string]string{},
		RouteLocalnetBridges: map[string]bool{},
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
	var peerHosts []metadata.Host
	peersLoaded := false
	for uuid, network := range networks {
		bridgeConfig, err := bridgeConfigForNetwork(network)
		if err != nil {
			return fmt.Errorf("network %s bridge configuration: %w", uuid, err)
		}
		if subnet := bridgeConfig.Subnet; subnet != "" {
			if bridgeConfig.Bridge == "" {
				return fmt.Errorf("network %s has a forward subnet but no managed bridge", uuid)
			}
			resolved, err := hostlabel.Resolve(subnet, host.Labels)
			if err != nil {
				return fmt.Errorf("network %s hostport subnet: %w", uuid, err)
			}
			newRules.ForwardSubnets[uuid] = resolved
			newRules.ForwardBridges[uuid] = bridgeConfig.Bridge
			if bridgeConfig.SharedIngress {
				if newRules.SharedIngress == nil {
					newRules.SharedIngress = map[string]bool{}
				}
				newRules.SharedIngress[uuid] = true
			}
			if hostlabel.IsReference(subnet) {
				if newRules.ForwardPeers == nil {
					newRules.ForwardPeers = map[string][]string{}
				}
				if !peersLoaded {
					peerHosts, err = w.c.GetHosts()
					if err != nil {
						return err
					}
					peersLoaded = true
				}
				newRules.ForwardPeers[uuid], err = hostlabel.PeerSubnets(subnet, host.UUID, resolved, peerHosts)
				if err != nil {
					return fmt.Errorf("network %s hostport peers: %w", uuid, err)
				}
			}
		}
	}

	containers, err := w.c.GetContainers()
	if err != nil {
		return err
	}

	for _, container := range containers {
		network := networks[container.NetworkUUID]
		bridge := ""
		masqueradeDNAT := false

		if container.State != "running" && container.State != "starting" {
			continue
		}

		if container.HostUUID != host.UUID ||
			!(network.HostPorts || (container.System && container.Labels[hostPortsLabel] == "true")) {
			continue
		}
		if len(container.Ports) == 0 {
			continue
		}

		bridgeConfig, err := bridgeConfigForNetwork(network)
		if err != nil {
			return fmt.Errorf("network %s bridge configuration: %w", container.NetworkUUID, err)
		}
		bridge, masqueradeDNAT = bridgeConfig.Bridge, bridgeConfig.ExternalGateway
		targetIP := container.PrimaryIp
		if targetIP == "" {
			subnet := newRules.ForwardSubnets[container.NetworkUUID]
			if subnet == "" {
				return fmt.Errorf("container %s (%s) publishes host ports without a metadata IP or managed subnet", container.Name, container.ExternalId)
			}
			resolveContainerIPv4 := w.containerIPv4
			if resolveContainerIPv4 == nil {
				resolveContainerIPv4 = w.resolveContainerIPv4
			}
			targetIP, err = resolveContainerIPv4(container.ExternalId, subnet)
			if err != nil {
				return fmt.Errorf("resolve host-port address for container %s (%s): %w", container.Name, container.ExternalId, err)
			}
		}

		for _, port := range container.Ports {
			rule, ok := parsePortRule(bridge, host.AgentIP, targetIP, port)
			if !ok {
				return fmt.Errorf("invalid host port definition for container %s (%s): %q", container.Name, container.ExternalId, port)
			}

			rule.MasqueradeDNAT = masqueradeDNAT
			newRules.Ports[container.ExternalId+"/"+port] = rule
			address, _ := netip.ParseAddr(rule.SourceIP)
			if rule.Bridge != "" && (rule.SourceIP == "0.0.0.0" || address.IsLoopback()) {
				newRules.RouteLocalnetBridges[rule.Bridge] = true
			}
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

func (w *watcher) resolveContainerIPv4(containerID, subnet string) (string, error) {
	if containerID == "" {
		return "", fmt.Errorf("Docker container ID is empty")
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("managed subnet %q is not a valid IPv4 prefix", subnet)
	}
	prefix = prefix.Masked()

	inspectPID := w.containerPID
	if inspectPID == nil {
		inspectPID = w.inspectRunningContainerPID
	}
	pid, err := inspectPID(containerID)
	if err != nil {
		return "", err
	}
	readAddresses := w.namespaceIPv4
	if readAddresses == nil {
		readAddresses = readContainerNamespaceIPv4
	}
	addresses, err := readAddresses(pid)
	if err != nil {
		return "", err
	}
	confirmedPID, err := inspectPID(containerID)
	if err != nil {
		return "", fmt.Errorf("revalidate Docker container after network namespace read: %w", err)
	}
	if confirmedPID != pid {
		return "", fmt.Errorf("Docker container PID changed during network namespace read: %d to %d", pid, confirmedPID)
	}
	return selectContainerIPv4(addresses, prefix)
}

func (w *watcher) inspectRunningContainerPID(containerID string) (int, error) {
	if w.dc == nil {
		return 0, fmt.Errorf("Docker client is unavailable")
	}
	inspectResult, err := w.dc.ContainerInspect(context.Background(), containerID, client.ContainerInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("inspect Docker container: %w", err)
	}
	state := inspectResult.Container.State
	if state == nil || !state.Running || state.Pid <= 0 {
		return 0, fmt.Errorf("Docker container is not running with a network namespace")
	}
	return state.Pid, nil
}

func readContainerNamespaceIPv4(pid int) ([]netlink.Addr, error) {
	ns, err := netns.GetFromPid(pid)
	if err != nil {
		return nil, fmt.Errorf("open network namespace: %w", err)
	}
	defer ns.Close()
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, fmt.Errorf("open netlink handle: %w", err)
	}
	defer handle.Delete()
	addresses, err := handle.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list network addresses: %w", err)
	}
	return addresses, nil
}

func selectContainerIPv4(addresses []netlink.Addr, prefix netip.Prefix) (string, error) {
	candidates := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.IPNet == nil {
			continue
		}
		parsed, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			continue
		}
		parsed = parsed.Unmap()
		if !parsed.Is4() || parsed.IsLoopback() || !prefix.Contains(parsed) {
			continue
		}
		duplicate := false
		for _, candidate := range candidates {
			if candidate == parsed {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, parsed)
		}
	}
	if len(candidates) != 1 {
		return "", fmt.Errorf("expected exactly one address in managed subnet %s, found %d", prefix, len(candidates))
	}
	return candidates[0].String(), nil
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
	buf.WriteString("*raw\n")
	buf.WriteString(fmt.Sprintf(":%s -\n", hostPortsRawChain))
	buf.WriteString(fmt.Sprintf("-F %s\n", hostPortsRawChain))
	for _, bridge := range sortedEnabledBridges(rules.RouteLocalnetBridges) {
		buf.WriteString(fmt.Sprintf("-A %s -i %s -d 127.0.0.0/8 -j DROP\n", hostPortsRawChain, bridge))
	}
	buf.WriteString("COMMIT\n\n")

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
	for _, network := range sortedForwardNetworks(rules) {
		buf.WriteString(fmt.Sprintf("-A CATTLE_FORWARD -i %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n", network.Bridge, network.Subnet))
		buf.WriteString(fmt.Sprintf("-A CATTLE_FORWARD -o %s -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", network.Bridge, network.Subnet))
	}
	for _, network := range sortedSharedIngressNetworks(rules) {
		buf.WriteString(fmt.Sprintf("-A CATTLE_FORWARD -o %s -s %s -d %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n", network.Bridge, network.Subnet, network.Subnet))
	}
	for _, pair := range sortedForwardPeers(rules) {
		buf.WriteString(fmt.Sprintf("-A CATTLE_FORWARD -o %s -s %s -d %s -j ACCEPT\n", pair.Bridge, pair.Peer, pair.Local))
	}
	// A nat-table MARK is evaluated only for the first packet of a conntracked
	// flow. In particular, subsequent VXLAN UDP datagrams can reach Docker's
	// unpublished-port DROP without the mark. Match only our published DNAT
	// targets here, so every packet in that flow is admitted without widening
	// access to unrelated Docker or host firewall rules.
	for _, key := range portKeys {
		p := rules.Ports[key]
		buf.WriteString(fmt.Sprintf("-A CATTLE_FORWARD -m conntrack --ctstate DNAT -d %s -p %s -m %s --dport %s -j ACCEPT\n", p.TargetIP, p.Protocol, p.Protocol, p.TargetPort))
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
	if err := w.restoreRemovedRouteLocalnet(rules); err != nil {
		return err
	}
	if err := w.restore(w.backend.Restore, []string{"-n"}, buf.Bytes()); err != nil {
		return fmt.Errorf("apply hostport rules: %w", err)
	}

	if err := w.insertBaseRules(); err != nil {
		return fmt.Errorf("apply port base iptables rules: %w", err)
	}
	if err := w.activateRouteLocalnet(rules); err != nil {
		return err
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
	for uuid, subnet := range rules.ForwardSubnets {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return fmt.Errorf("invalid IPv4 forward subnet %q", subnet)
		}
		bridge := rules.ForwardBridges[uuid]
		if err := validateBridgeName(bridge); err != nil {
			return fmt.Errorf("forward network %s: %w", uuid, err)
		}
	}
	for uuid := range rules.ForwardBridges {
		if rules.ForwardSubnets[uuid] == "" {
			return fmt.Errorf("forward bridge network %s has no local subnet", uuid)
		}
	}
	for uuid, enabled := range rules.SharedIngress {
		if enabled && (rules.ForwardSubnets[uuid] == "" || rules.ForwardBridges[uuid] == "") {
			return fmt.Errorf("shared ingress network %s has no managed bridge and subnet", uuid)
		}
	}
	for uuid, peers := range rules.ForwardPeers {
		if rules.ForwardSubnets[uuid] == "" {
			return fmt.Errorf("forward peer network %s has no local subnet", uuid)
		}
		if rules.ForwardBridges[uuid] == "" {
			return fmt.Errorf("forward peer network %s has no managed bridge", uuid)
		}
		for _, peer := range peers {
			prefix, err := netip.ParsePrefix(peer)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
				return fmt.Errorf("invalid IPv4 forward peer subnet %q", peer)
			}
		}
	}
	for bridge := range rules.RouteLocalnetBridges {
		if err := validateBridgeName(bridge); err != nil {
			return fmt.Errorf("route_localnet: %w", err)
		}
	}
	return nil
}

func validatePortRule(rule PortRule) error {
	if rule.Bridge != "" {
		if err := validateBridgeName(rule.Bridge); err != nil {
			return err
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

func validateBridgeName(bridge string) error {
	if bridge == "" || len(bridge) > 15 {
		return fmt.Errorf("invalid bridge name %q", bridge)
	}
	for _, char := range bridge {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.') {
			return fmt.Errorf("invalid bridge name %q", bridge)
		}
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

type bridgeNetworkConfig struct {
	Bridge          string
	Subnet          string
	ExternalGateway bool
	SharedIngress   bool
}

func bridgeConfigForNetwork(network metadata.Network) (bridgeNetworkConfig, error) {
	conf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	keys := make([]string, 0, len(conf))
	for key := range conf {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var result bridgeNetworkConfig
	resultKey := ""
	found := false
	for _, key := range keys {
		file := conf[key]
		props, _ := file.(map[string]interface{})
		cniType, _ := props["type"].(string)
		if !isBridgeCNIType(cniType) {
			continue
		}
		bridge, _ := props["bridge"].(string)
		bridgeSubnet, _ := props["bridgeSubnet"].(string)
		externalGateway, _ := props["skipBridgeConfigureIP"].(bool)
		hostNat, _ := props["hostNat"].(bool)
		sharedIngress := hostNat && bridgeSubnet != "" && !hostlabel.IsReference(bridgeSubnet)
		if configured, exists := props["allowSharedSubnetIngress"]; exists {
			value, ok := configured.(bool)
			if !ok {
				return bridgeNetworkConfig{}, fmt.Errorf("managed bridge entry %q has a non-boolean allowSharedSubnetIngress", key)
			}
			sharedIngress = value
		}
		if sharedIngress && hostlabel.IsReference(bridgeSubnet) {
			return bridgeNetworkConfig{}, fmt.Errorf("managed bridge entry %q cannot combine shared ingress with a host-label subnet", key)
		}
		candidate := bridgeNetworkConfig{Bridge: bridge, Subnet: bridgeSubnet, ExternalGateway: externalGateway, SharedIngress: sharedIngress}
		if !found {
			result = candidate
			resultKey = key
			found = true
			continue
		}
		if candidate != result {
			return bridgeNetworkConfig{}, fmt.Errorf("conflicting managed bridge entries %q and %q", resultKey, key)
		}
	}
	return result, nil
}

func forwardSubnetForNetwork(network metadata.Network) string {
	config, _ := bridgeConfigForNetwork(network)
	return config.Subnet
}

func hostportBridgeForNetwork(network metadata.Network) (string, bool) {
	config, _ := bridgeConfigForNetwork(network)
	return config.Bridge, config.ExternalGateway
}

func isBridgeCNIType(cniType string) bool {
	return cniType == "pasture-bridge" || cniType == "rancher-bridge"
}

type forwardNetwork struct{ UUID, Bridge, Subnet string }

func sortedForwardNetworks(rules ruleSet) []forwardNetwork {
	keys := make([]string, 0, len(rules.ForwardSubnets))
	for key := range rules.ForwardSubnets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	result := []forwardNetwork{}
	for _, key := range keys {
		network := forwardNetwork{UUID: key, Bridge: rules.ForwardBridges[key], Subnet: rules.ForwardSubnets[key]}
		identity := network.Bridge + "\x00" + network.Subnet
		if network.Bridge == "" || network.Subnet == "" || seen[identity] {
			continue
		}
		seen[identity] = true
		result = append(result, network)
	}
	return result
}

func sortedSharedIngressNetworks(rules ruleSet) []forwardNetwork {
	result := []forwardNetwork{}
	for _, network := range sortedForwardNetworks(rules) {
		if rules.SharedIngress[network.UUID] {
			result = append(result, network)
		}
	}
	return result
}

type forwardPair struct{ Peer, Local, Bridge string }

func sortedForwardPeers(rules ruleSet) []forwardPair {
	keys := make([]string, 0, len(rules.ForwardPeers))
	for key := range rules.ForwardPeers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := []forwardPair{}
	for _, key := range keys {
		peers := append([]string(nil), rules.ForwardPeers[key]...)
		sort.Strings(peers)
		for _, peer := range peers {
			pairs = append(pairs, forwardPair{Peer: peer, Local: rules.ForwardSubnets[key], Bridge: rules.ForwardBridges[key]})
		}
	}
	return pairs
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
		return fmt.Errorf("set net.bridge.bridge-nf-call-iptables: %w", err)
	}
	return nil
}
