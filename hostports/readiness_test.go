package hostports

import (
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
)

type badPortMetadata struct{ metadata.Client }

func (badPortMetadata) GetNetworks() ([]metadata.Network, error) {
	return []metadata.Network{{UUID: "net-1", HostPorts: true}}, nil
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
		applied: ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}},
	}
	err := w.onChange("test")
	if err == nil || !strings.Contains(err.Error(), "invalid host port definition") {
		t.Fatalf("invalid port was silently accepted: %v", err)
	}
	if !w.lastApplied.IsZero() {
		t.Fatal("failed reconcile changed applied state")
	}
}
