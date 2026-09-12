package hostports

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/moby/moby/client"
)

// This is deliberately absent from normal CI. Run only in a disposable VM
// with Docker's iptables firewall backend; never against a production host.
func TestIptablesNFTOnDisposableVM(t *testing.T) {
	testIptablesOnDisposableVM(t, firewall.IptablesNFT)
}

func TestIptablesLegacyOnDisposableVM(t *testing.T) {
	testIptablesOnDisposableVM(t, firewall.IptablesLegacy)
}

func testIptablesOnDisposableVM(t *testing.T, mode firewall.Mode) {
	if os.Getenv("PASTURESTACK_IPTABLES_VM_TEST") != "1" {
		t.Skip("requires explicit isolated VM opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("xtables integration test requires root in the disposable VM")
	}
	command, restore := string(mode), string(mode)+"-restore"
	for _, name := range []string{command, restore} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(name, "--version").CombinedOutput()
		marker := "nf_tables"
		if mode == firewall.IptablesLegacy {
			marker = "legacy"
		}
		if err != nil || !strings.Contains(string(out), marker) {
			t.Fatalf("%s is not the %s frontend: %v: %s", name, mode, err, out)
		}
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
	if info.Info.FirewallBackend == nil || info.Info.FirewallBackend.Driver != "iptables" {
		t.Fatalf("refusing xtables test outside Docker iptables mode: %#v", info.Info.FirewallBackend)
	}
	if out, err := exec.Command(command, "-t", "nat", "-S", "DOCKER").CombinedOutput(); err != nil {
		t.Fatalf("requires Docker-owned NAT chain in %s: %v: %s", mode, err, out)
	}
	other := "iptables-nft"
	if mode == firewall.IptablesNFT {
		other = "iptables-legacy"
	}
	if out, err := exec.Command(other, "-t", "nat", "-S", "DOCKER").CombinedOutput(); err == nil {
		t.Fatalf("refusing dual Docker backends; %s also owns NAT: %s", other, out)
	}
	for _, table := range []string{"nat", "filter"} {
		out, err := xtVMCommand(command, "-t", table, "-S")
		if err != nil {
			t.Fatalf("inspect existing %s rules: %v: %s", table, err, out)
		}
		if strings.Contains(string(out), "CATTLE_") {
			t.Fatalf("refusing to touch existing CATTLE chains in %s: %s", table, out)
		}
	}
	t.Cleanup(func() { cleanupXTTestRules(t, command) })
	rules := ruleSet{
		Ports: map[string]PortRule{
			"isolated": {Bridge: "pstest0", SourceIP: "198.51.100.2", SourcePort: "55555", TargetIP: "10.254.250.2", TargetPort: "55556", Protocol: "tcp"},
		},
		ForwardSubnets: map[string]string{"isolated": "10.254.250.0/24"},
	}
	w := &watcher{backend: firewall.Backend{Mode: mode, Command: command, Restore: restore}}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := w.apply(rules); err != nil {
			t.Fatalf("iptables-nft apply %d (includes --test -n): %v", attempt, err)
		}
		for _, hook := range []struct{ table, chain, target string }{
			{"nat", "PREROUTING", "CATTLE_PREROUTING"},
			{"nat", "OUTPUT", "CATTLE_OUTPUT"},
			{"nat", "POSTROUTING", hostPortsPostRoutingChain},
			{"filter", "FORWARD", "CATTLE_FORWARD"},
		} {
			out, err := xtVMCommand(command, "-t", hook.table, "-S", hook.chain)
			if err != nil {
				t.Fatalf("inspect %s/%s after apply %d: %v: %s", hook.table, hook.chain, attempt, err, out)
			}
			if got := strings.Count(string(out), "-j "+hook.target); got != 1 {
				t.Fatalf("%s/%s has %d jumps to %s after apply %d: %s", hook.table, hook.chain, got, hook.target, attempt, out)
			}
		}
	}
}

func xtVMCommand(command string, args ...string) ([]byte, error) {
	return exec.Command(command, append([]string{"-w"}, args...)...).CombinedOutput()
}

func cleanupXTTestRules(t *testing.T, command string) {
	for _, hook := range []struct {
		table, chain string
		spec         []string
	}{
		{"nat", "PREROUTING", []string{"-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_PREROUTING"}},
		{"nat", "OUTPUT", []string{"-m", "addrtype", "--dst-type", "LOCAL", "-j", "CATTLE_OUTPUT"}},
		{"nat", "POSTROUTING", []string{"-j", hostPortsPostRoutingChain}},
		{"filter", "FORWARD", []string{"-j", "CATTLE_FORWARD"}},
	} {
		check := append([]string{"-t", hook.table, "-C", hook.chain}, hook.spec...)
		deleteArgs := append([]string{"-t", hook.table, "-D", hook.chain}, hook.spec...)
		for {
			if _, err := xtVMCommand(command, check...); err != nil {
				break
			}
			if out, err := xtVMCommand(command, deleteArgs...); err != nil {
				t.Errorf("remove own hook %s/%s: %v: %s", hook.table, hook.chain, err, out)
				break
			}
		}
	}
	for _, entry := range []struct{ table, chain string }{
		{"nat", "CATTLE_PREROUTING"},
		{"nat", "CATTLE_POSTROUTING"},
		{"nat", "CATTLE_OUTPUT"},
		{"nat", hostPortsPostRoutingChain},
		{"filter", "CATTLE_FORWARD"},
	} {
		if _, err := xtVMCommand(command, "-t", entry.table, "-S", entry.chain); err != nil {
			continue // A failed apply may never have created this chain.
		}
		if out, err := xtVMCommand(command, "-t", entry.table, "-F", entry.chain); err != nil {
			t.Errorf("flush own chain %s/%s: %v: %s", entry.table, entry.chain, err, out)
			continue
		}
		if out, err := xtVMCommand(command, "-t", entry.table, "-X", entry.chain); err != nil {
			t.Errorf("delete own chain %s/%s: %v: %s", entry.table, entry.chain, err, out)
		}
	}
	for _, table := range []string{"nat", "filter"} {
		out, err := xtVMCommand(command, "-t", table, "-S")
		if err != nil {
			t.Errorf("verify %s cleanup: %v: %s", table, err, out)
		} else if strings.Contains(string(out), "CATTLE_") {
			t.Errorf("own rules remain in %s after cleanup: %s", table, out)
		}
	}
}
