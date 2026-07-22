package hostnat

import (
	"reflect"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
)

func TestNetworkToRuleSupportsPastureBridge(t *testing.T) {
	network := metadata.Network{
		Metadata: map[string]interface{}{
			"cniConfig": map[string]interface{}{
				"10-pasturestack.conf": map[string]interface{}{
					"type":         "pasture-bridge",
					"bridge":       "docker0",
					"bridgeSubnet": "10.42.0.0/16",
					"hostNat":      true,
				},
			},
		},
	}

	want := &MASQRule{Subnet: "10.42.0.0/16", Bridge: "docker0"}
	if got := (&watcher{}).networkToRule(network); !reflect.DeepEqual(got, want) {
		t.Fatalf("networkToRule() = %#v, want %#v", got, want)
	}
	if got := bridgeForNetwork(network); got != "docker0" {
		t.Fatalf("bridgeForNetwork() = %q, want docker0", got)
	}
}

func TestNetworkToRuleRetainsLegacyBridgeCompatibility(t *testing.T) {
	network := metadata.Network{
		Metadata: map[string]interface{}{
			"cniConfig": map[string]interface{}{
				"10-legacy.conf": map[string]interface{}{
					"type":         "rancher-bridge",
					"bridge":       "docker0",
					"bridgeSubnet": "10.42.0.0/16",
					"hostNat":      true,
				},
			},
		},
	}

	if got := (&watcher{}).networkToRule(network); got == nil {
		t.Fatal("networkToRule() did not retain the legacy bridge type")
	}
}

func TestIPsecOverlayContainerSupportsNativeAndLegacyIdentity(t *testing.T) {
	native := metadata.Container{Labels: map[string]string{"io.pasturestack.component": "ipsec-overlay"}}
	legacy := metadata.Container{StackName: "ipsec", ServiceName: "ipsec"}
	unrelated := metadata.Container{StackName: "application", ServiceName: "web"}

	if !isIPsecOverlayContainer(native) {
		t.Fatal("native overlay container was not recognized")
	}
	if !isIPsecOverlayContainer(legacy) {
		t.Fatal("legacy overlay container was not recognized")
	}
	if isIPsecOverlayContainer(unrelated) {
		t.Fatal("unrelated container was recognized as an overlay container")
	}
}
