package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/hostnat"
	"github.com/PastureStack/network-plugin-manager/hostports"
	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/PastureStack/network-plugin-manager/internal/readiness"
	"github.com/moby/moby/client"
)

// This opt-in test exercises the two firewall watchers and the same readiness
// tracker used by main, but deliberately does NOT launch the complete manager.
// The full process also runs reaper, CNI, MAC and route reconciliation, which
// must not be invoked just to test firewall readiness. The child is confined
// to a fresh Linux network namespace: nft tables cannot reach the VM host's
// namespace even though the Docker socket is used for a read-only Info call.
func TestFirewallWatchersReadinessOnDisposableVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_FIREWALL_WATCHERS_VM_TEST") != "1" {
		t.Skip("set PASTURESTACK_FIREWALL_WATCHERS_VM_TEST=1 only on an isolated Ubuntu VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated network namespace test requires root")
	}
	for _, name := range []string{"unshare", "ip", "nft", "sysctl"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PASTURESTACK_FIREWALL_WATCHERS_VM_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-n", "--", os.Args[0], "-test.run=^TestFirewallWatchersReadinessOnDisposableVM$", "-test.v")
		cmd.Env = append(os.Environ(), "PASTURESTACK_FIREWALL_WATCHERS_VM_CHILD=1", "PASTURESTACK_FIREWALL_WATCHERS_PARENT_NS="+parentNS)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated watcher test failed: %v\n%s", err, out)
		}
		t.Logf("isolated watcher test:\n%s", out)
		return
	}
	if parentNS == os.Getenv("PASTURESTACK_FIREWALL_WATCHERS_PARENT_NS") {
		t.Fatal("unshare did not create a separate network namespace")
	}
	vmWatcherReadinessInNamespace(t)
}

type vmMetadataSnapshot struct {
	mu       sync.Mutex
	revision int
	ready    bool
	badPort  bool
}

func (s *vmMetadataSnapshot) set(ready, badPort bool) {
	s.mu.Lock()
	s.ready, s.badPort = ready, badPort
	s.revision++
	s.mu.Unlock()
}

func (s *vmMetadataSnapshot) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	revision, ready, badPort := s.revision, s.ready, s.badPort
	s.mu.Unlock()
	if r.URL.Query().Get("wait") == "true" && r.URL.Query().Get("value") == fmt.Sprintf("revision-%d", revision) {
		time.Sleep(100 * time.Millisecond) // Avoid a busy-loop in the fake long poll.
	}
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/2016-07-29")
	var body interface{}
	switch path {
	case "/version":
		body = fmt.Sprintf("revision-%d", revision)
	case "/self/host":
		body = metadata.Host{UUID: "pst-vm-host", AgentIP: "192.0.2.10"}
	case "/hosts":
		if !ready {
			http.Error(w, "hosts not yet published", http.StatusServiceUnavailable)
			return
		}
		body = []metadata.Host{{UUID: "pst-vm-host", AgentIP: "192.0.2.10"}}
	case "/networks":
		body = []metadata.Network{{
			UUID: "pst-vm-network", HostPorts: true,
			Metadata: map[string]interface{}{"cniConfig": map[string]interface{}{
				"10-pasturestack.conf": map[string]interface{}{
					"type": "pasture-bridge", "bridge": "pstqa0", "bridgeSubnet": "198.18.230.0/24", "hostNat": true,
				},
			}},
		}}
	case "/containers":
		port := "0.0.0.0:39091:39092/tcp"
		if badPort {
			port = "0.0.0.0:invalid:39092/tcp"
		}
		body = []metadata.Container{{
			UUID: "pst-vm-container", ExternalId: "pst-vm-synthetic-container",
			HostUUID: "pst-vm-host", NetworkUUID: "pst-vm-network", State: "running",
			PrimaryIp: "198.18.230.2", Ports: []string{port},
		}}
	case "/services":
		body = []metadata.Service{}
	default:
		http.NotFound(w, r)
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		panic(err)
	}
}

func vmWatcherReadinessInNamespace(t *testing.T) {
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v: %s", err, out)
	}
	out, err := exec.Command("nft", "list", "tables", "ip").CombinedOutput()
	if err != nil {
		t.Fatalf("inspect isolated nft tables before test: %v: %s", err, out)
	}
	for _, table := range []string{"pasturestack_hostnat", "pasturestack_hostports"} {
		if strings.Contains(string(out), "table ip "+table+"\n") {
			t.Fatalf("refusing to replace existing table %s in isolated namespace", table)
		}
	}
	if out, err := exec.Command("ip", "link", "add", "pstqa0", "type", "bridge").CombinedOutput(); err != nil {
		t.Fatalf("create isolated test bridge: %v: %s", err, out)
	}
	t.Cleanup(func() {
		for _, table := range []string{"pasturestack_hostnat", "pasturestack_hostports"} {
			if _, err := exec.Command("nft", "list", "table", "ip", table).CombinedOutput(); err == nil {
				if out, err := exec.Command("nft", "delete", "table", "ip", table).CombinedOutput(); err != nil {
					t.Errorf("delete test-owned table %s: %v: %s", table, err, out)
				}
			}
		}
		if out, err := exec.Command("ip", "link", "delete", "pstqa0").CombinedOutput(); err != nil {
			t.Errorf("delete test-owned bridge: %v: %s", err, out)
		}
	})
	if out, err := exec.Command("ip", "link", "set", "pstqa0", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated test bridge: %v: %s", err, out)
	}

	dc, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	info, err := dc.Info(context.Background(), client.InfoOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Info.FirewallBackend == nil || info.Info.FirewallBackend.Driver != "nftables" {
		t.Fatalf("requires Docker native nftables on the disposable VM: %#v", info.Info.FirewallBackend)
	}

	snapshot := &vmMetadataSnapshot{revision: 1}
	server := httptest.NewServer(http.HandlerFunc(snapshot.serve))
	defer server.Close()
	mClient, err := metadata.NewClientAndWait(server.URL + "/2016-07-29")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "pasturestack-network-ready")
	status, err := readiness.New(marker)
	if err != nil {
		t.Fatal(err)
	}
	backend := firewall.Backend{Mode: firewall.NFTables, Command: "nft"}
	if err := hostnat.Watch(mClient, dc, backend, func(err error) { vmReportReadiness(t, status, readiness.HostNAT, err) }); err != nil {
		t.Fatal(err)
	}
	if err := hostports.Watch(mClient, dc, backend, func(err error) { vmReportReadiness(t, status, readiness.HostPorts, err) }); err != nil {
		t.Fatal(err)
	}
	// /version succeeds from the outset; /hosts does not. Neither watcher may
	// make the actual image HEALTHCHECK's file-existence condition true yet.
	time.Sleep(600 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("readiness appeared before host metadata was available: %v", err)
	}

	snapshot.set(true, false)
	vmWaitMarker(t, marker, true, 12*time.Second)
	for _, table := range []string{"pasturestack_hostnat", "pasturestack_hostports"} {
		out, err := exec.Command("nft", "list", "table", "ip", table).CombinedOutput()
		if err != nil {
			t.Fatalf("watcher did not install isolated %s: %v: %s", table, err, out)
		}
		if table == "pasturestack_hostnat" && !strings.Contains(string(out), "198.18.230.0/24") {
			t.Fatalf("hostnat did not apply expected subnet: %s", out)
		}
		if table == "pasturestack_hostports" && !strings.Contains(string(out), "39091") {
			t.Fatalf("hostports did not apply expected port: %s", out)
		}
	}

	snapshot.set(true, true)
	vmWaitMarker(t, marker, false, 12*time.Second)
	if out, err := exec.Command("nft", "list", "table", "ip", "pasturestack_hostports").CombinedOutput(); err != nil || !strings.Contains(string(out), "39091") {
		t.Fatalf("invalid hostport erased the last known-good rules: %v: %s", err, out)
	}
}

func vmReportReadiness(t *testing.T, status *readiness.Tracker, component readiness.Component, reconcileErr error) {
	t.Helper()
	if err := status.Report(component, reconcileErr); err != nil {
		t.Errorf("report %s readiness: %v", component, err)
	}
}

func vmWaitMarker(t *testing.T, marker string, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := os.Stat(marker)
		if (err == nil) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("readiness marker presence did not become %t within %s", want, timeout)
}
