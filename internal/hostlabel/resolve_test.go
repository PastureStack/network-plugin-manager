package hostlabel

import (
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
)

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		labels            map[string]string
		wantError         bool
	}{
		{name: "literal subnet", input: "10.42.0.0/16", want: "10.42.0.0/16"},
		{name: "host subnet", input: "__host_label__: io.pasturestack.network.per-host-subnet.subnet", labels: map[string]string{"io.pasturestack.network.per-host-subnet.subnet": "10.51.1.0/24"}, want: "10.51.1.0/24"},
		{name: "missing label", input: "__host_label__: io.pasturestack.network.per-host-subnet.subnet", wantError: true},
		{name: "empty key", input: "__host_label__: ", wantError: true},
		{name: "malformed key", input: "__host_label__: invalid key", wantError: true},
		{name: "invalid subnet", input: "__host_label__: subnet", labels: map[string]string{"subnet": "invalid"}, wantError: true},
		{name: "noncanonical subnet", input: "__host_label__: subnet", labels: map[string]string{"subnet": "10.51.1.4/24"}, wantError: true},
		{name: "rule injection", input: "__host_label__: subnet", labels: map[string]string{"subnet": "10.51.1.0/24\n-A INPUT -j ACCEPT"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.input, tc.labels)
			if (err != nil) != tc.wantError || got != tc.want {
				t.Fatalf("Resolve() = %q, %v; want %q, error=%v", got, err, tc.want, tc.wantError)
			}
		})
	}
}

func TestPeerSubnets(t *testing.T) {
	const reference = "__host_label__:subnet"
	hosts := []metadata.Host{
		{UUID: "local", State: "active", Labels: map[string]string{"subnet": "10.51.1.0/24"}},
		{UUID: "old", State: "reconnecting"},
		{UUID: "peer", State: "active", Labels: map[string]string{"subnet": "10.51.2.0/24"}},
	}
	got, err := PeerSubnets(reference, "local", "10.51.1.0/24", hosts)
	if err != nil || len(got) != 1 || got[0] != "10.51.2.0/24" {
		t.Fatalf("active peer subnets = %v, %v", got, err)
	}
	hosts[1].State = "active"
	if _, err := PeerSubnets(reference, "local", "10.51.1.0/24", hosts); err == nil {
		t.Fatal("active host missing its subnet was accepted")
	}
	hosts[1].Labels = map[string]string{"subnet": "10.51.1.128/25"}
	if _, err := PeerSubnets(reference, "local", "10.51.1.0/24", hosts); err == nil {
		t.Fatal("overlapping peer subnet was accepted")
	}
	if got, err := PeerSubnets("10.42.0.0/16", "local", "10.42.0.0/16", hosts); err != nil || len(got) != 0 {
		t.Fatalf("literal network unexpectedly added peer rules: %v, %v", got, err)
	}
}
