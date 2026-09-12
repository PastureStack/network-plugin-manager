package hostnat

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
)

// This opt-in test must run as root on a disposable Ubuntu 26.04 VM using
// Docker's native nftables backend. It applies the production watcher rules
// through a test-owned nft table and uses an isolated bridge/network namespace
// to prove that an otherwise unroutable 10.42/16 workload can reach the web.
func TestNativeNFTTrafficOnDisposableVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_NFT_TRAFFIC_VM_TEST") != "1" {
		t.Skip("set PASTURESTACK_NFT_TRAFFIC_VM_TEST=1 on an isolated root VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native nft traffic integration test requires root")
	}
	for _, name := range []string{"docker", "nft", "ip", "sysctl", "ping", "getent", "curl", "python3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	if out := vmNATCommand(t, "docker", "info", "--format", "{{.FirewallBackend.Driver}}"); strings.TrimSpace(out) != "nftables" {
		t.Fatalf("requires Docker native nftables backend; got %q", strings.TrimSpace(out))
	}
	if out := vmNATCommand(t, "sysctl", "-n", "net.ipv4.ip_forward"); strings.TrimSpace(out) != "1" {
		t.Fatalf("requires existing IPv4 forwarding; got %q (test will not change global policy)", strings.TrimSpace(out))
	}

	// PID-scoped names are short enough for Linux interfaces. Refuse to replace
	// any existing resource, including a route into the test subnet.
	id := fmt.Sprintf("%x", os.Getpid())
	bridge, hostVeth, nsVeth := "pnbr"+id, "pnvh"+id, "pnvn"+id
	ns, table := "pasture-nat-qa-"+id, "pasturestack_hostnat_traffic_"+id
	peerBridge, peerHostVeth, peerNSVeth := "prbr"+id, "prvh"+id, "prvn"+id
	peerNS := "pasture-nat-peer-" + id
	if len(bridge) > 15 || len(hostVeth) > 15 || len(nsVeth) > 15 || len(peerBridge) > 15 || len(peerHostVeth) > 15 || len(peerNSVeth) > 15 {
		t.Fatal("test interface name exceeds Linux IFNAMSIZ")
	}
	for _, dev := range []string{bridge, hostVeth, nsVeth, peerBridge, peerHostVeth, peerNSVeth} {
		if out, err := vmNATTry("ip", "link", "show", "dev", dev); err == nil {
			t.Fatalf("refusing to replace existing interface %s: %s", dev, out)
		}
	}
	for _, name := range []string{ns, peerNS} {
		if out := vmNATCommand(t, "ip", "netns", "list"); strings.Contains(out, name+" ") || strings.Contains(out, name+"\n") {
			t.Fatalf("refusing to replace existing network namespace %s", name)
		}
	}
	if out := vmNATCommand(t, "nft", "list", "tables", "ip"); strings.Contains(out, "table ip "+table) {
		t.Fatalf("refusing to replace existing nft table %s", table)
	}
	for _, subnet := range []string{"10.42.251.0/24", "10.42.252.0/24"} {
		if out := vmNATCommand(t, "ip", "route", "show", subnet); strings.TrimSpace(out) != "" {
			t.Fatalf("test subnet %s already routed on host: %s", subnet, out)
		}
	}
	confDir := filepath.Join("/etc/netns", ns)
	peerConfDir := filepath.Join("/etc/netns", peerNS)
	if _, err := os.Stat(confDir); err == nil {
		t.Fatalf("refusing to replace existing resolver directory %s", confDir)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := os.Stat(peerConfDir); err == nil {
		t.Fatalf("refusing to replace existing resolver directory %s", peerConfDir)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	resolver, err := vmNATResolver()
	if err != nil {
		t.Fatal(err)
	}

	bridgeMade, vethMade, nsMade, tableMade, resolverMade, resolverParentMade := false, false, false, false, false, false
	peerBridgeMade, peerVethMade, peerNSMade := false, false, false
	t.Cleanup(func() {
		if tableMade {
			vmNATCleanup(t, "nft", "delete", "table", "ip", table)
		}
		if vethMade {
			if _, err := vmNATTry("ip", "link", "show", "dev", hostVeth); err == nil {
				vmNATCleanup(t, "ip", "link", "del", hostVeth)
			}
		}
		if nsMade {
			vmNATCleanup(t, "ip", "netns", "del", ns)
		}
		if bridgeMade {
			vmNATCleanup(t, "ip", "link", "del", bridge)
		}
		if peerVethMade {
			if _, err := vmNATTry("ip", "link", "show", "dev", peerHostVeth); err == nil {
				vmNATCleanup(t, "ip", "link", "del", peerHostVeth)
			}
		}
		if peerNSMade {
			vmNATCleanup(t, "ip", "netns", "del", peerNS)
		}
		if peerBridgeMade {
			vmNATCleanup(t, "ip", "link", "del", peerBridge)
		}
		if resolverMade {
			if err := os.Remove(filepath.Join(confDir, "resolv.conf")); err != nil {
				t.Errorf("remove test resolver: %v", err)
			}
			if err := os.Remove(confDir); err != nil {
				t.Errorf("remove test resolver directory: %v", err)
			}
		}
		if resolverParentMade {
			if err := os.Remove("/etc/netns"); err != nil {
				t.Errorf("remove empty test-created /etc/netns directory: %v", err)
			}
		}
	})

	vmNATCommand(t, "ip", "link", "add", bridge, "type", "bridge")
	bridgeMade = true
	vmNATCommand(t, "ip", "addr", "add", "10.42.251.1/24", "dev", bridge)
	vmNATCommand(t, "ip", "link", "set", bridge, "up")
	vmNATCommand(t, "ip", "netns", "add", ns)
	nsMade = true
	vmNATCommand(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	vethMade = true
	vmNATCommand(t, "ip", "link", "set", hostVeth, "master", bridge)
	vmNATCommand(t, "ip", "link", "set", hostVeth, "up")
	vmNATCommand(t, "ip", "link", "set", nsVeth, "netns", ns)
	vmNATCommand(t, "ip", "netns", "exec", ns, "ip", "addr", "add", "10.42.251.2/24", "dev", nsVeth)
	vmNATCommand(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	vmNATCommand(t, "ip", "netns", "exec", ns, "ip", "link", "set", nsVeth, "up")
	vmNATCommand(t, "ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", "10.42.251.1")
	vmNATCommand(t, "ip", "link", "add", peerBridge, "type", "bridge")
	peerBridgeMade = true
	vmNATCommand(t, "ip", "addr", "add", "10.42.252.1/24", "dev", peerBridge)
	vmNATCommand(t, "ip", "link", "set", peerBridge, "up")
	vmNATCommand(t, "ip", "netns", "add", peerNS)
	peerNSMade = true
	vmNATCommand(t, "ip", "link", "add", peerHostVeth, "type", "veth", "peer", "name", peerNSVeth)
	peerVethMade = true
	vmNATCommand(t, "ip", "link", "set", peerHostVeth, "master", peerBridge)
	vmNATCommand(t, "ip", "link", "set", peerHostVeth, "up")
	vmNATCommand(t, "ip", "link", "set", peerNSVeth, "netns", peerNS)
	vmNATCommand(t, "ip", "netns", "exec", peerNS, "ip", "addr", "add", "10.42.252.2/24", "dev", peerNSVeth)
	vmNATCommand(t, "ip", "netns", "exec", peerNS, "ip", "link", "set", "lo", "up")
	vmNATCommand(t, "ip", "netns", "exec", peerNS, "ip", "link", "set", peerNSVeth, "up")
	vmNATCommand(t, "ip", "netns", "exec", peerNS, "ip", "route", "add", "default", "via", "10.42.252.1")
	if _, err := os.Stat("/etc/netns"); os.IsNotExist(err) {
		if err := os.Mkdir("/etc/netns", 0755); err != nil {
			t.Fatal(err)
		}
		resolverParentMade = true
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	resolverMade = true
	if err := os.WriteFile(filepath.Join(confDir, "resolv.conf"), []byte("nameserver "+resolver+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// A successful pre-apply probe means an unrelated NAT path could produce a
	// false positive, so refuse to report this test as a manager success.
	if out, err := vmNATTry("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "2", "1.1.1.1"); err == nil {
		t.Fatalf("namespace already has internet egress without manager NAT: %s", out)
	}

	rules := ruleSet{MASQ: map[string]MASQRule{"qa": {Subnet: "10.42.0.0/16", Bridge: bridge}}, IKE: map[string]IKEPortSNATRule{}}
	w := &watcher{backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"}}
	w.nftRules = func(script []byte, check bool) error {
		if !bytes.Contains(script, []byte(nftNATTable)) {
			return fmt.Errorf("production hostnat table name absent from batch")
		}
		isolated := bytes.ReplaceAll(script, []byte(nftNATTable), []byte(table))
		args := []string{"-f", "-"}
		if check {
			args = append([]string{"-c"}, args...)
		}
		cmd := exec.Command("nft", args...)
		cmd.Stdin = bytes.NewReader(isolated)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft check=%t: %w: %s", check, err, out)
		}
		if !check {
			tableMade = true
		}
		return nil
	}
	if err := w.apply(rules); err != nil {
		t.Fatalf("apply production hostnat rules to isolated table: %v", err)
	}
	if out := vmNATCommand(t, "nft", "list", "chain", "ip", table, "postrouting"); !strings.Contains(out, "10.42.0.0/16") || !strings.Contains(out, "masquerade") {
		t.Fatalf("production MASQ rule missing: %s", out)
	}
	if got := vmNATPeerObservedSource(t, ns, peerNS); got != "10.42.251.2" {
		t.Fatalf("overlay-to-overlay packet was SNATed: source=%s, want 10.42.251.2", got)
	}
	vmNATCommand(t, "ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "5", "1.1.1.1")
	if out := vmNATCommand(t, "ip", "netns", "exec", ns, "getent", "ahostsv4", "example.com"); strings.TrimSpace(out) == "" {
		t.Fatal("DNS returned no IPv4 address")
	}
	if out := vmNATCommand(t, "ip", "netns", "exec", ns, "curl", "-4", "--fail", "--silent", "--show-error", "--max-time", "20", "-I", "https://example.com"); !strings.Contains(out, "HTTP/") {
		t.Fatalf("HTTPS returned no HTTP response: %s", out)
	}
	t.Log("production hostnat preserved overlay peer source and enabled isolated 10.42/16 IPv4 egress, DNS and HTTPS on Docker native nftables")
}

func vmNATPeerObservedSource(t *testing.T, sourceNS, peerNS string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, "ip", "netns", "exec", peerNS, "python3", "-u", "-c", `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.42.252.2", 43291))
s.settimeout(10)
print("READY", flush=True)
_, address = s.recvfrom(32)
print(address[0], flush=True)`)
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = server.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(ready) != "READY" {
		t.Fatalf("overlay peer did not start: ready=%q error=%v stderr=%s", ready, err, stderr.String())
	}
	vmNATCommand(t, "ip", "netns", "exec", sourceNS, "python3", "-c", `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"overlay-source-check", ("10.42.252.2", 43291))`)
	observed, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("overlay peer did not receive packet: %v: %s", err, stderr.String())
	}
	err = server.Wait()
	waited = true
	if err != nil {
		t.Fatalf("overlay peer failed: %v: %s", err, stderr.String())
	}
	return strings.TrimSpace(observed)
}

func vmNATResolver() (string, error) {
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[0] != "nameserver" {
				continue
			}
			ip := net.ParseIP(fields[1])
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no non-loopback IPv4 resolver found for isolated namespace")
}

func vmNATCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := vmNATTry(name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func vmNATCleanup(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := vmNATTry(name, args...); err != nil {
		t.Errorf("cleanup %s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
}

func vmNATTry(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
