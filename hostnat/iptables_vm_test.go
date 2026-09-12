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
	if os.Getenv("PASTURESTACK_IPTABLES_VM_TEST") != "1" {
		t.Skip("set PASTURESTACK_IPTABLES_VM_TEST=1 on an isolated root VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("iptables integration test requires root")
	}
	for _, name := range []string{"iptables-nft", "iptables-nft-restore"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	iptables := func(args ...string) ([]byte, error) {
		return exec.Command("iptables-nft", args...).CombinedOutput()
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
		backend: firewall.Backend{Mode: firewall.IptablesNFT, Command: "iptables-nft", Restore: "iptables-nft-restore"},
		restoreRules: func(name string, script []byte, check bool) error {
			if name != "iptables-nft-restore" {
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
		if err := w.apply(ruleSet{}); err != nil {
			t.Fatalf("apply iteration %d: %v", iteration, err)
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
