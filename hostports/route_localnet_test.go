package hostports

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
)

func routeLocalnetTestWatcher(t *testing.T, calls *[]string) *watcher {
	t.Helper()
	return &watcher{
		backend: firewall.Backend{Mode: firewall.IptablesNFT, Command: "iptables-nft", Restore: "iptables-nft-restore"},
		restoreRules: func(_ string, args []string, _ []byte) error {
			if reflect.DeepEqual(args, []string{"--test", "-n"}) {
				*calls = append(*calls, "precheck")
			} else if reflect.DeepEqual(args, []string{"-n"}) {
				*calls = append(*calls, "apply")
			}
			return nil
		},
		runCommand: func(...string) error { return nil },
		output: func(...string) ([]byte, error) {
			return []byte("-A FORWARD -j CATTLE_FORWARD\n"), nil
		},
		getRouteLocalnet: func(string) (bool, error) {
			*calls = append(*calls, "read-original")
			return false, nil
		},
		setRouteLocalnet: func(_ string, enabled bool) error {
			*calls = append(*calls, "set:"+map[bool]string{false: "0", true: "1"}[enabled])
			return nil
		},
		routeLocalnetOriginal:  map[string]bool{},
		routeLocalnetStatePath: filepath.Join(t.TempDir(), "route-localnet.json"),
		applied:                ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{}},
	}
}

func TestRouteLocalnetGuardAndRestoreOrdering(t *testing.T) {
	var calls []string
	w := routeLocalnetTestWatcher(t, &calls)
	rules := ruleSet{
		Ports:          map[string]PortRule{"port": {Bridge: "flatbr0", SourceIP: "0.0.0.0", SourcePort: "18045", TargetIP: "192.0.2.20", TargetPort: "42", Protocol: "tcp"}},
		ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{},
		RouteLocalnetBridges: map[string]bool{"flatbr0": true},
	}
	if err := w.apply(rules); err != nil {
		t.Fatal(err)
	}
	if got, want := calls, []string{"precheck", "apply", "read-original", "set:1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("enable order = %v, want %v", got, want)
	}
	state, err := loadRouteLocalnetState(w.routeLocalnetStatePath)
	if err != nil || len(state) != 1 || state["flatbr0"] {
		t.Fatalf("persisted original = %v, err=%v", state, err)
	}

	calls = nil
	empty := ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{}}
	if err := w.apply(empty); err != nil {
		t.Fatal(err)
	}
	if got, want := calls, []string{"precheck", "set:0", "apply"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("disable order = %v, want %v", got, want)
	}
	state, err = loadRouteLocalnetState(w.routeLocalnetStatePath)
	if err != nil || len(state) != 0 {
		t.Fatalf("state after restore = %v, err=%v", state, err)
	}
}

func TestRouteLocalnetPrecheckFailureDoesNotMutateSysctl(t *testing.T) {
	var calls []string
	w := routeLocalnetTestWatcher(t, &calls)
	w.restoreRules = func(_ string, args []string, _ []byte) error {
		calls = append(calls, strings.Join(args, " "))
		return errors.New("invalid batch")
	}
	rules := ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{"flatbr0": true}}
	if err := w.apply(rules); err == nil {
		t.Fatal("expected precheck failure")
	}
	if got, want := calls, []string{"--test -n"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("calls after failed precheck = %v, want %v", got, want)
	}
}

func TestForwardSubnetWithoutBridgeFailsBeforeFirewallMutation(t *testing.T) {
	var calls []string
	w := routeLocalnetTestWatcher(t, &calls)
	rules := ruleSet{
		Ports:          map[string]PortRule{},
		ForwardSubnets: map[string]string{"network": "10.42.0.0/16"},
		ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{},
	}
	if err := w.apply(rules); err == nil || !strings.Contains(err.Error(), "invalid bridge name") {
		t.Fatalf("missing bridge error = %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("firewall or sysctl mutated before bridge validation: %v", calls)
	}
}

func TestNativeNFTRouteLocalnetTransitionOrdering(t *testing.T) {
	var calls []string
	w := routeLocalnetTestWatcher(t, &calls)
	w.backend = firewall.Backend{Mode: firewall.NFTables}
	w.output = func(...string) ([]byte, error) { return []byte(""), nil }
	w.restoreRules = func(_ string, args []string, _ []byte) error {
		calls = append(calls, "nft:"+strings.Join(args, " "))
		return nil
	}
	rules := ruleSet{
		Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{},
		RouteLocalnetBridges: map[string]bool{"flatbr0": true},
	}
	if err := w.apply(rules); err != nil {
		t.Fatal(err)
	}
	if got, want := calls, []string{"nft:-c -f -", "nft:-f -", "read-original", "set:1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("native nft enable order = %v, want %v", got, want)
	}

	calls = nil
	empty := ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{}}
	if err := w.apply(empty); err != nil {
		t.Fatal(err)
	}
	if got, want := calls, []string{"nft:-c -f -", "set:0", "nft:-f -"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("native nft disable order = %v, want %v", got, want)
	}
}

func TestRouteLocalnetGuardIsBridgeScopedAcrossBackends(t *testing.T) {
	rules := ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}, ForwardBridges: map[string]string{}, RouteLocalnetBridges: map[string]bool{"flatbr0": true}}
	var xtables string
	w := &watcher{
		backend:      firewall.Backend{Mode: firewall.IptablesLegacy, Command: "iptables-legacy", Restore: "iptables-legacy-restore"},
		restoreRules: func(_ string, _ []string, data []byte) error { xtables = string(data); return nil },
		runCommand:   func(...string) error { return nil },
		output:       func(...string) ([]byte, error) { return []byte("-A FORWARD -j CATTLE_FORWARD\n"), nil },
	}
	if err := w.apply(rules); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(xtables, "-A CATTLE_HOSTPORTS_RAW -i flatbr0 -d 127.0.0.0/8 -j DROP") {
		t.Fatal("xtables guard is missing or not bridge-scoped")
	}
	native := string(nftHostportBatch(rules, false))
	if !strings.Contains(native, "iifname \"flatbr0\" ip daddr 127.0.0.0/8 drop") {
		t.Fatal("native nft guard is missing or not bridge-scoped")
	}
}

func TestConflictingManagedBridgeMetadataFailsClosed(t *testing.T) {
	network := metadata.Network{Metadata: map[string]interface{}{"cniConfig": map[string]interface{}{
		"10-a.conf": map[string]interface{}{"type": "pasture-bridge", "bridge": "flatbr0", "bridgeSubnet": "192.0.2.0/24"},
		"20-b.conf": map[string]interface{}{"type": "pasture-bridge", "bridge": "flatbr1", "bridgeSubnet": "198.51.100.0/24"},
	}}}
	if _, err := bridgeConfigForNetwork(network); err == nil {
		t.Fatal("conflicting bridge metadata was accepted")
	}
}
