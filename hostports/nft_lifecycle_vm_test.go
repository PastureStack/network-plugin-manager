package hostports

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
)

type nftLifecycleMetadata struct{ metadata.Client }

func (nftLifecycleMetadata) GetNetworks() ([]metadata.Network, error) {
	return []metadata.Network{{
		UUID: "test-network", HostPorts: true,
		Metadata: map[string]interface{}{"cniConfig": map[string]interface{}{
			"10-test.conf": map[string]interface{}{
				"type": "pasture-bridge", "bridge": "pstest0", "bridgeSubnet": "10.254.250.0/24",
			},
		}},
	}}, nil
}

func (nftLifecycleMetadata) GetContainers() ([]metadata.Container, error) {
	return []metadata.Container{{
		ExternalId: "test-container", Name: "test-container", HostUUID: "test-host",
		NetworkUUID: "test-network", State: "running", PrimaryIp: "10.254.250.2",
		Ports: []string{"198.51.100.2:19090:18080/tcp"},
	}}, nil
}

// This opt-in test runs every nft operation in an unshared network namespace.
// It neither contacts Docker nor changes the VM host firewall. The outer test
// has no nft side effects; unshare runs a child copy of this single test.
func TestNativeNFTLifecycleInUnsharedVMNamespace(t *testing.T) {
	if os.Getenv("PASTURESTACK_NFT_LIFECYCLE_VM_TEST") != "1" {
		t.Skip("requires explicit root test on an isolated Linux VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network namespace and nft test require root")
	}
	for _, name := range []string{"nft", "unshare"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("PASTURESTACK_NFT_LIFECYCLE_CHILD") != "1" {
		cmd := exec.Command("unshare", "-n", "--", os.Args[0], "-test.run=^TestNativeNFTLifecycleInUnsharedVMNamespace$", "-test.v")
		cmd.Env = append(os.Environ(), "PASTURESTACK_NFT_LIFECYCLE_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated namespace test failed: %v: %s", err, out)
		} else {
			t.Logf("isolated namespace result: %s", strings.TrimSpace(string(out)))
		}
		return
	}
	if out, err := exec.Command("nft", "list", "table", "ip", nftHostportsTable).CombinedOutput(); err == nil {
		t.Fatalf("refusing to replace an existing table in child namespace: %s", out)
	}
	t.Cleanup(func() {
		if _, err := exec.Command("nft", "list", "table", "ip", nftHostportsTable).CombinedOutput(); err == nil {
			if out, err := exec.Command("nft", "delete", "table", "ip", nftHostportsTable).CombinedOutput(); err != nil {
				t.Errorf("remove isolated test table: %v: %s", err, out)
			}
		}
	})
	w := &watcher{
		c:       nftLifecycleMetadata{},
		backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		localHost: func(metadata.Client, *client.Client) (metadata.Host, error) {
			return metadata.Host{UUID: "test-host", AgentIP: "198.51.100.2"}, nil
		},
		applied: ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}},
	}
	if err := w.onChange("initial"); err != nil {
		t.Fatalf("initial production nft apply: %v", err)
	}
	if err := w.checkNFTRules(); err != nil {
		t.Fatalf("real nft JSON did not match production table: %v", err)
	}
	var reports []error
	w.report = func(err error) { reports = append(reports, err) }
	if out, err := exec.Command("nft", "delete", "table", "ip", nftHostportsTable).CombinedOutput(); err != nil {
		t.Fatalf("simulate Docker/external table deletion: %v: %s", err, out)
	}
	if err := w.repairOnce(); err != nil {
		t.Fatalf("restore deleted own nft table: %v", err)
	}
	if len(reports) != 2 || reports[0] == nil || reports[1] != nil {
		t.Fatalf("deleted-table readiness sequence = %v, want unhealthy then healthy", reports)
	}
	if err := w.checkNFTRules(); err != nil {
		t.Fatalf("recovered table invalid: %v", err)
	}
	reports = nil
	if out, err := exec.Command("nft", "flush", "chain", "ip", nftHostportsTable, "forward").CombinedOutput(); err != nil {
		t.Fatalf("simulate external forward rule flush: %v: %s", err, out)
	}
	if err := w.repairOnce(); err != nil {
		t.Fatalf("restore flushed own forward chain: %v", err)
	}
	if len(reports) != 2 || reports[0] == nil || reports[1] != nil {
		t.Fatalf("flushed-rule readiness sequence = %v, want unhealthy then healthy", reports)
	}
	if err := w.checkNFTRules(); err != nil {
		t.Fatalf("recovered forward chain invalid: %v", err)
	}
	reports = nil
	if out, err := exec.Command("nft", "delete", "table", "ip", nftHostportsTable).CombinedOutput(); err != nil {
		t.Fatalf("simulate second table deletion: %v: %s", err, out)
	}
	w.restoreRules = func(_ string, _ []string, _ []byte) error { return errors.New("injected preflight failure") }
	if err := w.repairOnce(); err == nil {
		t.Fatal("injected rebuild failure was ignored")
	}
	if len(reports) != 2 || reports[0] == nil || reports[1] == nil {
		t.Fatalf("failed-rebuild readiness sequence = %v, must stay unhealthy", reports)
	}
	if _, err := exec.Command("nft", "list", "table", "ip", nftHostportsTable).CombinedOutput(); err == nil {
		t.Fatal("failed preflight unexpectedly restored table")
	}
}
