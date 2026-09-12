package hostnat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
)

// This is opt-in because it requires CAP_NET_ADMIN. It uses a test-specific
// table and never flushes or deletes Docker's or the production table.
func TestNFTBatchOnVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_NFT_VM_TEST") != "1" {
		t.Skip("set PASTURESTACK_NFT_VM_TEST=1 on an isolated root VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("nft integration test requires root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatal(err)
	}
	table := fmt.Sprintf("pasturestack_hostnat_qa_%d", os.Getpid())
	if out, err := exec.Command("nft", "list", "tables", "ip").CombinedOutput(); err != nil {
		t.Fatalf("list ip tables before test: %v: %s", err, out)
	} else if strings.Contains(string(out), "table ip "+table) {
		t.Fatalf("refusing to replace pre-existing table %s", table)
	}
	rules := ruleSet{
		MASQ: map[string]MASQRule{"test": {Subnet: "198.18.0.0/15", Bridge: "pstqa0"}},
		IKE:  map[string]IKEPortSNATRule{"test": {SourceIP: "198.18.0.1", HostIP: "192.0.2.2", Bridge: "pstqa0", Port: "500"}},
	}
	if err := validateNATRules(rules); err != nil {
		t.Fatal(err)
	}
	script := nftNATScriptForTable(rules, table)
	created := false
	t.Cleanup(func() {
		if !created {
			return
		}
		if out, err := exec.Command("nft", "delete", "table", "ip", table).CombinedOutput(); err != nil {
			t.Errorf("delete test-owned table %s: %v: %s", table, err, out)
		}
	})
	for i := 0; i < 2; i++ {
		for _, check := range []bool{true, false} {
			args := []string{"-f", "-"}
			if check {
				args = append([]string{"-c"}, args...)
			} else {
				created = true
			}
			cmd := exec.Command("nft", args...)
			cmd.Stdin = bytes.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("batch iteration %d check=%t: %v: %s\n%s", i, check, err, out, script)
			}
		}
		out, err := exec.Command("nft", "list", "chain", "ip", table, "postrouting").CombinedOutput()
		if err != nil {
			t.Fatalf("read applied test chain: %v: %s", err, out)
		}
		if !bytes.Contains(out, []byte("masquerade")) || !bytes.Contains(out, []byte("snat to 192.0.2.2:500")) {
			t.Fatalf("test NAT rules missing after iteration %d: %s", i, out)
		}
		if got := bytes.Count(out, []byte("masquerade")); got != 4 {
			t.Fatalf("iteration %d accumulated duplicate MASQ rules: got %d, want 4:\n%s", i, got, out)
		}
	}
}

// Exercises recovery after an external deletion/flush without touching the
// production table or Docker's native nft tables. The test owns one uniquely
// named table and deliberately substitutes that name in both nft commands.
func TestNFTReconcileAfterOwnedTableLossOnVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_NFT_VM_TEST") != "1" {
		t.Skip("set PASTURESTACK_NFT_VM_TEST=1 on an isolated root VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("nft integration test requires root")
	}
	table := fmt.Sprintf("pasturestack_hostnat_qa_recovery_%d", os.Getpid())
	if out, err := exec.Command("nft", "list", "table", "ip", table).CombinedOutput(); err == nil {
		t.Fatalf("refusing to replace pre-existing test table %s: %s", table, out)
	}
	t.Cleanup(func() {
		if _, err := exec.Command("nft", "list", "table", "ip", table).CombinedOutput(); err != nil {
			return
		}
		if out, err := exec.Command("nft", "delete", "table", "ip", table).CombinedOutput(); err != nil {
			t.Errorf("remove test-owned table: %v: %s", err, out)
		}
	})
	rules := ruleSet{MASQ: map[string]MASQRule{"test": {Subnet: "198.18.0.0/15", Bridge: "pstqa0"}}}
	var reports []error
	w := &watcher{
		backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		nftRules: func(script []byte, check bool) error {
			isolated := bytes.ReplaceAll(script, []byte(nftNATTable), []byte(table))
			args := []string{"-f", "-"}
			if check {
				args = append([]string{"-c"}, args...)
			}
			cmd := exec.Command("nft", args...)
			cmd.Stdin = bytes.NewReader(isolated)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("nft test-owned table check=%t: %w: %s", check, err, out)
			}
			return nil
		},
		nftState: func() ([]byte, error) {
			out, err := exec.Command("nft", "-j", "list", "chain", "ip", table, "postrouting").CombinedOutput()
			return bytes.ReplaceAll(out, []byte(table), []byte(nftNATTable)), err
		},
		runRules: func(...string) error { return nil },
		report:   func(err error) { reports = append(reports, err) },
	}
	if err := w.apply(rules); err != nil {
		t.Fatal(err)
	}
	for _, loss := range []string{"delete", "flush", "wrong-hook"} {
		switch loss {
		case "delete":
			if out, err := exec.Command("nft", "delete", "table", "ip", table).CombinedOutput(); err != nil {
				t.Fatalf("delete test-owned table: %v: %s", err, out)
			}
		case "flush":
			if out, err := exec.Command("nft", "flush", "chain", "ip", table, "postrouting").CombinedOutput(); err != nil {
				t.Fatalf("flush test-owned chain: %v: %s", err, out)
			}
		case "wrong-hook":
			if out, err := exec.Command("nft", "delete", "table", "ip", table).CombinedOutput(); err != nil {
				t.Fatalf("delete test-owned table before wrong hook: %v: %s", err, out)
			}
			wrong := []byte("add table ip " + table + "\nadd chain ip " + table + " postrouting { type nat hook postrouting priority 105; policy accept; }\n")
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = bytes.NewReader(wrong)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("install wrong hook in test-owned table: %v: %s", err, out)
			}
		}
		w.lastApplied = time.Now()
		before := len(reports)
		w.reconcileNativeState()
		if len(reports) != before+2 || reports[before] == nil || reports[before+1] != nil {
			t.Fatalf("loss=%s readiness reports=%v", loss, reports[before:])
		}
		if err := w.checkNativeState(); err != nil {
			t.Fatalf("loss=%s owned hook did not recover: %v", loss, err)
		}
	}
}
