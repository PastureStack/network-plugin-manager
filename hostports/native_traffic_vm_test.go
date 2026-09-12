package hostports

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/moby/moby/client"
)

// Run only as root on a disposable Docker-native nftables VM. It uses one
// precisely named test container and an otherwise absent platform-owned nft
// table; it never modifies Docker's tables or another host's configuration.
func TestNativeHostportTrafficOnDisposableVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_NFT_TRAFFIC_VM_TEST") != "1" {
		t.Skip("requires explicit isolated VM opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in an isolated VM")
	}
	hostIP := os.Getenv("PASTURESTACK_VM_HOST_IP")
	if parsed := net.ParseIP(hostIP); parsed == nil || parsed.To4() == nil || parsed.IsLoopback() {
		t.Fatalf("set PASTURESTACK_VM_HOST_IP to the isolated VM's IPv4 address, got %q", hostIP)
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
		t.Fatalf("refusing traffic test outside Docker native nftables: info=%#v", info.Info.FirewallBackend)
	}
	if out, err := exec.Command("nft", "list", "table", "ip", nftHostportsTable).CombinedOutput(); err == nil {
		t.Fatalf("refusing to replace existing %s: %s", nftHostportsTable, out)
	}
	name := "pasturestack-hostport-traffic-vm-qa"
	if out, err := exec.Command("docker", "inspect", name).CombinedOutput(); err == nil {
		t.Fatalf("refusing to replace existing test container: %s", out)
	}
	clientNetwork := "pasturestack-hostport-client-vm-qa"
	if out, err := exec.Command("docker", "network", "inspect", clientNetwork).CombinedOutput(); err == nil {
		t.Fatalf("refusing to replace existing test network: %s", out)
	}
	if out, err := exec.Command("docker", "network", "create", clientNetwork).CombinedOutput(); err != nil {
		t.Fatalf("create isolated client bridge: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "network", "rm", clientNetwork).CombinedOutput(); err != nil {
			t.Errorf("remove own test client network: %v: %s", err, out)
		}
	})
	out, err := exec.Command("docker", "run", "-d", "--pull=never", "--name", name,
		"alpine:3.23", "sh", "-c", "while true; do printf 'manager-ok\\n' | nc -l -p 18080 -w 3; done").CombinedOutput()
	if err != nil {
		t.Fatalf("start test container: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("remove own test container: %v: %s", err, out)
		}
	})
	out, err = exec.Command("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect test container IP: %v: %s", err, out)
	}
	target := strings.TrimSpace(string(out))
	if net.ParseIP(target) == nil {
		t.Fatalf("invalid test container IP: %q", target)
	}
	w := &watcher{backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"}}
	rules := ruleSet{Ports: map[string]PortRule{"qa": {
		Bridge: "docker0", SourceIP: hostIP, SourcePort: "19090", TargetIP: target, TargetPort: "18080", Protocol: "tcp",
	}}}
	if err := w.apply(rules); err != nil {
		t.Fatalf("apply actual manager hostport rules: %v", err)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("nft", "delete", "table", "ip", nftHostportsTable).CombinedOutput(); err != nil {
			t.Errorf("remove own test nft table: %v: %s", err, out)
		}
	})
	for attempt := 0; attempt < 5; attempt++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(hostIP, "19090"), 2*time.Second)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			var response = make([]byte, 32)
			n, readErr := conn.Read(response)
			_ = conn.Close()
			if readErr == nil && strings.Contains(string(response[:n]), "manager-ok") {
				break
			}
			err = fmt.Errorf("read response: %v, data=%q", readErr, response[:n])
		}
		if attempt == 4 {
			t.Fatalf("hostport traffic did not reach test container: %v", err)
		}
		time.Sleep(time.Second)
	}
	// A separate bridge-network container reaches the host address through
	// PREROUTING/FORWARD, including Docker's later native bridge firewall hook.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := fmt.Sprintf("echo | nc -w 3 %s 19090", hostIP)
	sameBridge, sameBridgeErr := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull=never", "alpine:3.23", "sh", "-c", command).CombinedOutput()
	if sameBridgeErr != nil || !strings.Contains(string(sameBridge), "manager-ok") {
		t.Fatalf("same-bridge hostport hairpin failed: %v: %s", sameBridgeErr, sameBridge)
	}
	out, err = exec.CommandContext(ctx, "docker", "run", "--rm", "--network", clientNetwork, "--pull=never", "alpine:3.23", "sh", "-c", command).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "manager-ok") {
		t.Fatalf("forwarded Docker bridge client cannot reach manager hostport: %v: %s", err, out)
	}
}
