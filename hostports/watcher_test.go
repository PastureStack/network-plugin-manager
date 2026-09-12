package hostports

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
)

func TestForwardSubnetSupportsPastureBridge(t *testing.T) {
	network := metadata.Network{
		Metadata: map[string]interface{}{
			"cniConfig": map[string]interface{}{
				"10-pasturestack.conf": map[string]interface{}{
					"type":         "pasture-bridge",
					"bridgeSubnet": "10.42.0.0/16",
				},
			},
		},
	}

	if got := forwardSubnetForNetwork(network); got != "10.42.0.0/16" {
		t.Fatalf("forwardSubnetForNetwork() = %q, want 10.42.0.0/16", got)
	}
}

func TestBridgeTypeRetainsLegacyCompatibility(t *testing.T) {
	if !isBridgeCNIType("pasture-bridge") || !isBridgeCNIType("rancher-bridge") {
		t.Fatal("expected native and legacy bridge types to be supported")
	}
	if isBridgeCNIType("bridge") {
		t.Fatal("unexpected bridge type was accepted")
	}
}

func TestForwardJumpIsFirst(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "cattle first",
			out: strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j CATTLE_FORWARD",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			}, "\n"),
			want: true,
		},
		{
			name: "docker first",
			out: strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
				"-A FORWARD -j CATTLE_FORWARD",
			}, "\n"),
			want: false,
		},
		{
			name: "missing",
			out: strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			}, "\n"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := forwardJumpIsFirst([]byte(tt.out)); got != tt.want {
				t.Fatalf("forwardJumpIsFirst() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnsureForwardJumpFirstReordersExistingRule(t *testing.T) {
	var commands [][]string

	w := &watcher{
		output: func(args ...string) ([]byte, error) {
			commands = append(commands, append([]string(nil), args...))
			return []byte(strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
				"-A FORWARD -j CATTLE_FORWARD",
			}, "\n")), nil
		},
		runCommand: func(args ...string) error {
			commands = append(commands, append([]string(nil), args...))
			return nil
		},
	}

	if err := w.ensureForwardJumpFirst("iptables"); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"iptables", "-w", "-S", "FORWARD"},
		{"iptables", "-w", "-I", "FORWARD", "1", "-j", "CATTLE_FORWARD"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}

func TestEnsureForwardJumpFirstFailedInsertKeepsOldHook(t *testing.T) {
	var commands [][]string
	w := &watcher{
		output: func(args ...string) ([]byte, error) {
			return []byte("-A FORWARD -j DOCKER-USER\n-A FORWARD -j CATTLE_FORWARD\n"), nil
		},
		runCommand: func(args ...string) error {
			commands = append(commands, append([]string(nil), args...))
			return errors.New("insert denied")
		},
	}
	if err := w.ensureForwardJumpFirst("iptables"); err == nil {
		t.Fatal("expected insert failure")
	}
	if len(commands) != 1 || commands[0][3] != "FORWARD" || commands[0][2] != "-I" {
		t.Fatalf("unexpected commands: %v", commands)
	}
}

func TestEnsureForwardJumpFirstLeavesCorrectOrderAlone(t *testing.T) {
	var commands [][]string
	w := &watcher{
		output: func(args ...string) ([]byte, error) {
			commands = append(commands, append([]string(nil), args...))
			return []byte(strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j CATTLE_FORWARD",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			}, "\n")), nil
		},
		runCommand: func(args ...string) error {
			commands = append(commands, append([]string(nil), args...))
			return nil
		},
	}

	if err := w.ensureForwardJumpFirst("iptables"); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"iptables", "-w", "-S", "FORWARD"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}

func testRuleSet() ruleSet {
	return ruleSet{
		Ports: map[string]PortRule{
			"container/80:80:8080/tcp": {Bridge: "cattle0", SourceIP: "0.0.0.0", SourcePort: "80", TargetIP: "10.42.1.2", TargetPort: "8080", Protocol: "tcp"},
		},
		ForwardSubnets: map[string]string{"network": "10.42.0.0/16"},
	}
}

func TestBoundHostIPIsRespectedInLocalOutput(t *testing.T) {
	p := PortRule{SourceIP: "192.0.2.5", SourcePort: "443", TargetIP: "10.42.1.2", TargetPort: "8443", Protocol: "tcp"}
	if got := string(p.iptables()); !strings.Contains(got, "-A CATTLE_OUTPUT -p tcp -m tcp --dport 443 -m addrtype --dst-type LOCAL -d 192.0.2.5 -j DNAT") {
		t.Fatalf("iptables OUTPUT ignores bound IP: %s", got)
	}
	rules := ruleSet{Ports: map[string]PortRule{"bound": p}, ForwardSubnets: map[string]string{}}
	if got := string(nftHostportBatch(rules, false)); !strings.Contains(got, "fib daddr type local ip daddr 192.0.2.5 tcp dport 443 dnat") {
		t.Fatalf("nft OUTPUT ignores bound IP: %s", got)
	}
}

func TestApplyIptablesValidatesBeforeUpdatingOrRepairingHooks(t *testing.T) {
	var calls []string
	w := &watcher{
		backend: firewall.Backend{Mode: firewall.IptablesNFT, Command: "iptables-nft", Restore: "iptables-nft-restore"},
		restoreRules: func(name string, args []string, data []byte) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if !strings.Contains(string(data), "-A CATTLE_FORWARD -s 10.42.0.0/16") {
				t.Fatal("missing forward rule")
			}
			return nil
		},
		runCommand: func(args ...string) error {
			calls = append(calls, strings.Join(args, " "))
			return nil
		},
		output: func(args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			return []byte("-A FORWARD -j CATTLE_FORWARD\n"), nil
		},
	}
	if err := w.apply(testRuleSet()); err != nil {
		t.Fatal(err)
	}
	if len(calls) < 3 || calls[0] != "iptables-nft-restore --test -n" || calls[1] != "iptables-nft-restore -n" {
		t.Fatalf("wrong validation/update order: %v", calls)
	}
	for _, call := range calls {
		if strings.Contains(call, "iptables-legacy") || strings.Contains(call, " -D ") || strings.Contains(call, " -X ") {
			t.Fatalf("unexpected legacy or destructive hook operation: %s", call)
		}
	}
}

func TestApplyIptablesFailedPrecheckPreservesHooks(t *testing.T) {
	var calls []string
	w := &watcher{
		backend: firewall.Backend{Mode: firewall.IptablesNFT, Command: "iptables-nft", Restore: "iptables-nft-restore"},
		restoreRules: func(name string, args []string, data []byte) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return errors.New("bad rule")
		},
		runCommand: func(args ...string) error {
			t.Fatal("must not touch hooks after precheck failure")
			return nil
		},
	}
	if err := w.apply(testRuleSet()); err == nil {
		t.Fatal("expected precheck failure")
	}
	if !reflect.DeepEqual(calls, []string{"iptables-nft-restore --test -n"}) {
		t.Fatalf("commands = %v", calls)
	}
}

func TestApplyRejectsInvalidMetadataBeforeFirewallMutation(t *testing.T) {
	rules := testRuleSet()
	rules.ForwardSubnets["network"] = "10.42.0.0/16\nflush ruleset"
	w := &watcher{restoreRules: func(string, []string, []byte) error {
		t.Fatal("invalid metadata reached firewall")
		return nil
	}}
	if err := w.apply(rules); err == nil {
		t.Fatal("expected invalid subnet rejection")
	}
	rules = testRuleSet()
	bad := rules.Ports["container/80:80:8080/tcp"]
	bad.Bridge = "cattle0\nflush"
	rules.Ports["container/80:80:8080/tcp"] = bad
	if err := w.apply(rules); err == nil {
		t.Fatal("expected invalid bridge rejection")
	}
	rules = testRuleSet()
	rules.ForwardSubnets["network"] = "0.0.0.0/0"
	if err := w.apply(rules); err == nil {
		t.Fatal("must not mark the entire Internet as a managed network")
	}
}

func TestNativeNFTUsesOwnedTableAndSingleCheckedBatch(t *testing.T) {
	var checks, applies []byte
	w := &watcher{
		backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		output: func(args ...string) ([]byte, error) {
			if !reflect.DeepEqual(args, []string{"nft", "list", "tables"}) {
				t.Fatalf("unexpected command %v", args)
			}
			return []byte("table ip docker-bridges\ntable ip pasturestack_hostports\n"), nil
		},
		restoreRules: func(name string, args []string, data []byte) error {
			if name != "nft" {
				t.Fatalf("unexpected backend %q", name)
			}
			if reflect.DeepEqual(args, []string{"-c", "-f", "-"}) {
				checks = append([]byte(nil), data...)
			} else if reflect.DeepEqual(args, []string{"-f", "-"}) {
				applies = append([]byte(nil), data...)
			} else {
				t.Fatalf("unexpected nft flags %v", args)
			}
			return nil
		},
	}
	if err := w.apply(testRuleSet()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checks, applies) || len(checks) == 0 {
		t.Fatal("validation and apply did not use identical complete batch")
	}
	for _, expected := range []string{
		"delete table ip pasturestack_hostports",
		"table ip pasturestack_hostports {",
		"type nat hook prerouting priority -101",
		"type nat hook output priority -101",
		"type nat hook postrouting priority 99",
		"type filter hook forward priority -1",
		"meta mark & 0x1068 == 0x1068 accept",
		"ip saddr 10.42.0.0/16 ip daddr 10.42.0.0/16 meta mark set meta mark | 0x1068 accept",
	} {
		if !strings.Contains(string(checks), expected) {
			t.Fatalf("batch missing %q", expected)
		}
	}
	for _, forbidden := range []string{"delete table ip docker-bridges", "flush ruleset", "policy drop", "iptables-legacy"} {
		if strings.Contains(string(checks), forbidden) {
			t.Fatalf("batch contains forbidden operation %q", forbidden)
		}
	}
}

func TestNativeNFTFailedPrecheckDoesNotApply(t *testing.T) {
	applyCalled := false
	w := &watcher{
		backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		output: func(args ...string) ([]byte, error) {
			return []byte("table ip pasturestack_hostports\n"), nil
		},
		restoreRules: func(_ string, args []string, _ []byte) error {
			if reflect.DeepEqual(args, []string{"-c", "-f", "-"}) {
				return errors.New("invalid nft batch")
			}
			applyCalled = true
			return nil
		},
	}
	if err := w.apply(testRuleSet()); err == nil {
		t.Fatal("expected precheck failure")
	}
	if applyCalled || !w.lastApplied.IsZero() {
		t.Fatal("failed precheck changed applied state")
	}
}

// This opt-in test is intended for a disposable nft-only VM. It never touches
// Docker's tables and refuses to overwrite a pre-existing PastureStack table.
func TestNativeNFTOnDisposableVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_NFT_VM_TEST") != "1" {
		t.Skip("requires explicit isolated VM opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("nft integration test requires root in the disposable VM")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatal(err)
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
		t.Fatalf("refusing native nft test outside Docker nftables mode: %#v", info.Info.FirewallBackend)
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Fatalf("cannot inspect nft tables: %v: %s", err, out)
	}
	if out, err := exec.Command("nft", "list", "table", "ip", nftHostportsTable).CombinedOutput(); err == nil {
		t.Fatalf("refusing to overwrite pre-existing table: %s", out)
	}
	defer func() {
		if out, err := exec.Command("nft", "delete", "table", "ip", nftHostportsTable).CombinedOutput(); err != nil {
			t.Errorf("clean up isolated nft table: %v: %s", err, out)
		}
	}()
	w := &watcher{backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"}}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := w.apply(testRuleSet()); err != nil {
			t.Fatalf("native nft attempt %d: %v", attempt, err)
		}
		out, err := exec.Command("nft", "list", "table", "ip", nftHostportsTable).CombinedOutput()
		if err != nil {
			t.Fatalf("inspect own table after attempt %d: %v: %s", attempt, err, out)
		}
		for _, expected := range []string{"hook prerouting", "hook output", "hook postrouting", "hook forward", "10.42.0.0/16"} {
			if !bytes.Contains(out, []byte(expected)) {
				t.Fatalf("table missing %q after attempt %d: %s", expected, attempt, out)
			}
		}
	}
}
