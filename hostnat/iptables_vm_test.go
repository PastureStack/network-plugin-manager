package hostnat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
)

// Opt-in root test for an isolated VM. It refuses to run when the production
// chain/hook already exists and removes only what this test creates.
func TestIptablesNFTBatchOnVM(t *testing.T) {
	testIptablesBatchOnVM(t, firewall.IptablesNFT)
}

func TestIptablesLegacyBatchOnVM(t *testing.T) {
	testIptablesBatchOnVM(t, firewall.IptablesLegacy)
}

func testIptablesBatchOnVM(t *testing.T, mode firewall.Mode) {
	if os.Getenv("PASTURESTACK_IPTABLES_VM_TEST") != "1" {
		t.Skip("set PASTURESTACK_IPTABLES_VM_TEST=1 on an isolated root VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("iptables integration test requires root")
	}
	command, restore := string(mode), string(mode)+"-restore"
	for _, name := range []string{command, restore} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.FirewallBackend.Driver}}").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "iptables" {
		t.Fatalf("requires Docker iptables backend: %v: %s", err, out)
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
	iptables := func(args ...string) ([]byte, error) {
		return exec.Command(command, args...).CombinedOutput()
	}
	postrouting, err := iptables("-t", "nat", "-S", "POSTROUTING")
	if err != nil {
		t.Fatalf("cannot inspect POSTROUTING before test: %v: %s", err, postrouting)
	}
	if out, err := iptables("-t", "nat", "-S", natChain); err == nil {
		t.Fatalf("refusing to modify pre-existing %s chain: %s", natChain, out)
	}
	if bytes.Contains(postrouting, []byte("-j "+natChain)) {
		t.Fatalf("refusing to modify pre-existing %s hook", natChain)
	}
	const bridge = "docker0"
	setting := "net.ipv4.conf." + bridge + ".route_localnet"
	previous, err := exec.Command("sysctl", "-n", setting).CombinedOutput()
	if err != nil {
		t.Fatalf("read %s before test: %v: %s", setting, err, previous)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("sysctl", "-w", setting+"="+strings.TrimSpace(string(previous))).CombinedOutput(); err != nil {
			t.Errorf("restore %s: %v: %s", setting, err, out)
		}
	})

	owned := false
	t.Cleanup(func() {
		if !owned {
			return
		}
		if out, err := iptables("-t", "nat", "-S", natChain); err != nil {
			// A failed preflight or atomic restore may have created nothing.
			return
		} else if len(out) == 0 {
			return
		}
		for i := 0; i < 3; i++ {
			if _, err := iptables("-t", "nat", "-C", "POSTROUTING", "-j", natChain); err != nil {
				break
			}
			if out, err := iptables("-t", "nat", "-D", "POSTROUTING", "-j", natChain); err != nil {
				t.Errorf("remove test-owned NAT hook: %v: %s", err, out)
				return
			}
		}
		if out, err := iptables("-t", "nat", "-F", natChain); err != nil {
			t.Errorf("flush test-owned NAT chain: %v: %s", err, out)
			return
		}
		if out, err := iptables("-t", "nat", "-X", natChain); err != nil {
			t.Errorf("delete test-owned NAT chain: %v: %s", err, out)
		}
	})

	iteration := 0
	w := watcher{
		backend: firewall.Backend{Mode: mode, Command: command, Restore: restore},
		restoreRules: func(name string, script []byte, check bool) error {
			if name != restore {
				return fmt.Errorf("unexpected restore binary %s", name)
			}
			if iteration > 0 {
				if out, err := iptables("-t", "nat", "-C", "POSTROUTING", "-j", natChain); err != nil {
					return fmt.Errorf("existing hook removed before restore check=%t: %w: %s", check, err, out)
				}
			}
			args := []string{"-n"}
			if check {
				args = append(args, "--test")
			}
			cmd := exec.Command(name, args...)
			cmd.Stdin = bytes.NewReader(script)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
			}
			if iteration == 0 && check {
				if out, err := iptables("-t", "nat", "-S", natChain); err == nil {
					return fmt.Errorf("restore --test unexpectedly created %s: %s", natChain, out)
				}
			}
			return nil
		},
	}
	for iteration = 0; iteration < 2; iteration++ {
		owned = true // cleanup also covers a partial failure after this point
		if err := w.apply(ruleSet{MASQ: map[string]MASQRule{"qa": {Subnet: "198.18.250.0/24", Bridge: bridge}}}); err != nil {
			t.Fatalf("apply iteration %d: %v", iteration, err)
		}
		masq, err := iptables("-t", "nat", "-S", natChain)
		if err != nil || strings.Count(string(masq), "! -d 198.18.250.0/24") != 3 {
			t.Fatalf("same-subnet egress exclusion missing after apply %d: %v: %s", iteration, err, masq)
		}
		out, err := iptables("-t", "nat", "-S", "POSTROUTING")
		if err != nil {
			t.Fatalf("read POSTROUTING after iteration %d: %v: %s", iteration, err, out)
		}
		if got := strings.Count(string(out), "-j "+natChain); got != 1 {
			t.Fatalf("iteration %d has %d base hooks, want one: %s", iteration, got, out)
		}
	}
}
