package hostports

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
)

type badPortMetadata struct{ metadata.Client }

func (badPortMetadata) GetNetworks() ([]metadata.Network, error) {
	return []metadata.Network{{UUID: "net-1", HostPorts: true}}, nil
}

func netlinkAddress(cidr string) netlink.Addr {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: network.Mask}}
}

func TestSelectContainerIPv4IsScopedAndUnambiguous(t *testing.T) {
	prefix := netip.MustParsePrefix("10.50.1.0/24")
	addresses := []netlink.Addr{
		netlinkAddress("127.0.0.1/8"),
		netlinkAddress("192.0.2.9/24"),
		netlinkAddress("10.50.1.2/24"),
		netlinkAddress("10.50.1.2/32"),
	}
	got, err := selectContainerIPv4(addresses, prefix)
	if err != nil || got != "10.50.1.2" {
		t.Fatalf("scoped address = %q, %v", got, err)
	}
	addresses = append(addresses, netlinkAddress("10.50.1.3/24"))
	if _, err := selectContainerIPv4(addresses, prefix); err == nil || !strings.Contains(err.Error(), "found 2") {
		t.Fatalf("ambiguous managed addresses were accepted: %v", err)
	}
}

func TestResolveContainerIPv4RevalidatesContainerPID(t *testing.T) {
	pidCalls := 0
	w := &watcher{
		containerPID: func(string) (int, error) {
			pidCalls++
			if pidCalls == 1 {
				return 101, nil
			}
			return 202, nil
		},
		namespaceIPv4: func(pid int) ([]netlink.Addr, error) {
			if pid != 101 {
				t.Fatalf("namespace reader PID = %d, want 101", pid)
			}
			return []netlink.Addr{netlinkAddress("10.50.1.2/24")}, nil
		},
	}
	if _, err := w.resolveContainerIPv4("container-1", "10.50.1.0/24"); err == nil || !strings.Contains(err.Error(), "PID changed") {
		t.Fatalf("PID lifecycle race was not rejected: %v", err)
	}
}

func TestResolveContainerIPv4AcceptsStableContainerPID(t *testing.T) {
	pidCalls := 0
	w := &watcher{
		containerPID: func(string) (int, error) {
			pidCalls++
			return 101, nil
		},
		namespaceIPv4: func(pid int) ([]netlink.Addr, error) {
			return []netlink.Addr{netlinkAddress("10.50.1.2/24")}, nil
		},
	}
	got, err := w.resolveContainerIPv4("container-1", "10.50.1.0/24")
	if err != nil || got != "10.50.1.2" {
		t.Fatalf("stable namespace address = %q, %v", got, err)
	}
	if pidCalls != 2 {
		t.Fatalf("container PID inspected %d times, want 2", pidCalls)
	}
}

type missingPrimaryIPMetadata struct{ metadata.Client }

func (missingPrimaryIPMetadata) GetNetworks() ([]metadata.Network, error) {
	return []metadata.Network{{
		UUID: "net-1", HostPorts: true,
		Metadata: map[string]interface{}{"cniConfig": map[string]interface{}{
			"10-per-host.conf": map[string]interface{}{
				"type": "pasture-bridge", "bridge": "cattle0", "bridgeSubnet": "10.50.1.0/24",
			},
		}},
	}}, nil
}

func (missingPrimaryIPMetadata) GetContainers() ([]metadata.Container, error) {
	return []metadata.Container{{
		ExternalId: "container-1", HostUUID: "host-1", NetworkUUID: "net-1",
		Name: "probe", State: "running", Ports: []string{"0.0.0.0:18084:8080/tcp"},
	}}, nil
}

func TestMissingMetadataIPUsesManagedNamespaceAddress(t *testing.T) {
	var gotContainerID, gotSubnet string
	w := &watcher{
		c: missingPrimaryIPMetadata{},
		localHost: func(metadata.Client, *client.Client) (metadata.Host, error) {
			return metadata.Host{UUID: "host-1", AgentIP: "192.0.2.10"}, nil
		},
		containerIPv4: func(containerID, subnet string) (string, error) {
			gotContainerID, gotSubnet = containerID, subnet
			return "10.50.1.2", nil
		},
		applied: ruleSet{
			Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{},
		},
		backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		output: func(_ ...string) ([]byte, error) {
			return nil, nil
		},
		getRouteLocalnet:       func(string) (bool, error) { return false, nil },
		setRouteLocalnet:       func(string, bool) error { return nil },
		routeLocalnetOriginal:  map[string]bool{},
		routeLocalnetStatePath: t.TempDir() + "/route-localnet.json",
		restoreRules: func(_ string, _ []string, data []byte) error {
			if !strings.Contains(string(data), "10.50.1.2:8080") {
				t.Fatalf("resolved CNI address was not used in host-port rules: %s", data)
			}
			return nil
		},
	}
	if err := w.onChange("test"); err != nil {
		t.Fatal(err)
	}
	if gotContainerID != "container-1" || gotSubnet != "10.50.1.0/24" {
		t.Fatalf("resolver arguments = %q, %q", gotContainerID, gotSubnet)
	}
}

func TestMissingMetadataIPWithoutManagedSubnetFailsClosed(t *testing.T) {
	clientWithoutSubnet := badPortMetadata{}
	w := &watcher{
		c: clientWithoutSubnet,
		localHost: func(metadata.Client, *client.Client) (metadata.Host, error) {
			return metadata.Host{UUID: "host-1", AgentIP: "192.0.2.10"}, nil
		},
		applied: ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{}},
	}
	containers, _ := clientWithoutSubnet.GetContainers()
	containers[0].PrimaryIp = ""
	containers[0].Ports = []string{"0.0.0.0:18084:8080/tcp"}
	w.c = &singleContainerMetadata{network: metadata.Network{UUID: "net-1", HostPorts: true}, container: containers[0]}
	if err := w.onChange("test"); err == nil || !strings.Contains(err.Error(), "without a metadata IP or managed subnet") {
		t.Fatalf("missing address boundary was not rejected: %v", err)
	}
}

type singleContainerMetadata struct {
	metadata.Client
	network   metadata.Network
	container metadata.Container
}

func (m *singleContainerMetadata) GetNetworks() ([]metadata.Network, error) {
	return []metadata.Network{m.network}, nil
}

func (m *singleContainerMetadata) GetContainers() ([]metadata.Container, error) {
	return []metadata.Container{m.container}, nil
}

func (badPortMetadata) GetContainers() ([]metadata.Container, error) {
	return []metadata.Container{{
		ExternalId: "container-1", HostUUID: "host-1", NetworkUUID: "net-1",
		State: "running", PrimaryIp: "10.42.0.2", Ports: []string{"invalid-port"},
	}}, nil
}

func TestMalformedEligibleHostPortFailsReconcileWithoutApplying(t *testing.T) {
	w := &watcher{
		c: badPortMetadata{},
		localHost: func(metadata.Client, *client.Client) (metadata.Host, error) {
			return metadata.Host{UUID: "host-1", AgentIP: "192.0.2.10"}, nil
		},
		applied: ruleSet{
			Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{},
		},
	}
	err := w.onChange("test")
	if err == nil || !strings.Contains(err.Error(), "invalid host port definition") {
		t.Fatalf("invalid port was silently accepted: %v", err)
	}
	if !w.lastApplied.IsZero() {
		t.Fatal("failed reconcile changed applied state")
	}
}
