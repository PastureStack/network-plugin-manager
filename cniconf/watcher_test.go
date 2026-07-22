package cniconf

import (
	"reflect"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
)

func TestLocalCNINetworksUsesLocalDriverPresence(t *testing.T) {
	networks := []metadata.Network{
		{
			UUID: "network-ipsec",
			Metadata: map[string]interface{}{
				"cniConfig": map[string]interface{}{
					"10-pasturestack.conf": map[string]interface{}{"type": "pasture-bridge"},
				},
			},
		},
		{
			UUID:     "network-host",
			Metadata: map[string]interface{}{},
		},
	}
	services := []metadata.Service{
		{
			Kind: "networkDriverService",
			Containers: []metadata.Container{
				{
					HostUUID:    "host-local",
					NetworkUUID: "network-host",
				},
			},
		},
	}

	got := localCNINetworks(networks, services, "host-local")
	want := map[string]bool{"network-ipsec": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("localCNINetworks() = %v, want %v", got, want)
	}
}

func TestLocalCNINetworksRequiresDriverOnThisHost(t *testing.T) {
	networks := []metadata.Network{
		{
			UUID: "network-ipsec",
			Metadata: map[string]interface{}{
				"cniConfig": map[string]interface{}{},
			},
		},
	}
	services := []metadata.Service{
		{
			Kind: "networkDriverService",
			Containers: []metadata.Container{
				{HostUUID: "host-remote", NetworkUUID: "network-host"},
			},
		},
	}

	if got := localCNINetworks(networks, services, "host-local"); len(got) != 0 {
		t.Fatalf("localCNINetworks() = %v, want no networks", got)
	}
}

func TestLocalCNINetworksIgnoresNetworksWithoutCNIConfig(t *testing.T) {
	networks := []metadata.Network{
		{UUID: "network-host", Metadata: map[string]interface{}{}},
		{UUID: "network-invalid", Metadata: map[string]interface{}{"cniConfig": "invalid"}},
	}
	services := []metadata.Service{
		{
			Kind: "networkDriverService",
			Containers: []metadata.Container{
				{HostUUID: "host-local", NetworkUUID: "network-host"},
			},
		},
	}

	if got := localCNINetworks(networks, services, "host-local"); len(got) != 0 {
		t.Fatalf("localCNINetworks() = %v, want no networks", got)
	}
}
