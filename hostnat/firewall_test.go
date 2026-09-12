package hostnat

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
)

func TestNATRejectsMalformedMetadataBeforeMutation(t *testing.T) {
	cases := map[string]ruleSet{
		"global-subnet": {MASQ: map[string]MASQRule{"n": {Subnet: "0.0.0.0/0", Bridge: "pst0"}}},
		"subnet":        {MASQ: map[string]MASQRule{"n": {Subnet: "10.42.0.0/16\nflush ruleset", Bridge: "pst0"}}},
		"bridge":        {MASQ: map[string]MASQRule{"n": {Subnet: "10.42.0.0/16", Bridge: "pst0\nflush"}}},
		"source":        {IKE: map[string]IKEPortSNATRule{"c": {SourceIP: "10.0.0.1; flush ruleset", HostIP: "10.0.0.2", Port: "500"}}},
		"host":          {IKE: map[string]IKEPortSNATRule{"c": {SourceIP: "10.0.0.1", HostIP: "10.0.0.2; flush", Port: "500"}}},
		"port":          {IKE: map[string]IKEPortSNATRule{"c": {SourceIP: "10.0.0.1", HostIP: "10.0.0.2", Port: "500; flush ruleset"}}},
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			w := watcher{backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"}, nftRules: func([]byte, bool) error {
				called = true
				return nil
			}}
			if err := w.apply(rules); err == nil {
				t.Fatal("invalid metadata was accepted")
			}
			if called {
				t.Fatal("nft was called before validation")
			}
		})
	}
}

func TestNATNativeStateChecksOwnedHookAndRules(t *testing.T) {
	rules := ruleSet{MASQ: map[string]MASQRule{"n": {Subnet: "10.42.0.0/16", Bridge: "pst0"}}}
	w := watcher{backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"}, applied: rules}
	for _, tc := range []struct {
		name      string
		data      string
		wantError bool
	}{
		{"intact", nftStateFixture(true, 4), false},
		{"flushed", nftStateFixture(true, 0), true},
		{"hook-removed", nftStateFixture(false, 4), true},
		{"missing-table", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w.nftState = func() ([]byte, error) {
				if tc.name == "missing-table" {
					return nil, errors.New("No such file or directory")
				}
				return []byte(tc.data), nil
			}
			if err := w.checkNativeState(); (err != nil) != tc.wantError {
				t.Fatalf("check error=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestNATNativeDriftReportsUnhealthyBeforeRecoveryAndRetries(t *testing.T) {
	rules := ruleSet{MASQ: map[string]MASQRule{"n": {Subnet: "10.42.0.0/16", Bridge: "pst0"}}}
	lost := true
	reject := true
	var statuses []error
	var checks []bool
	w := watcher{
		backend:     firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		applied:     rules,
		lastApplied: time.Now(),
		nftState: func() ([]byte, error) {
			if lost {
				return nil, errors.New("owned table missing")
			}
			return []byte(nftStateFixture(true, 4)), nil
		},
		nftRules: func(_ []byte, check bool) error {
			checks = append(checks, check)
			if reject {
				return errors.New("preflight failed")
			}
			if !check {
				lost = false
			}
			return nil
		},
		runRules: func(...string) error { return nil },
		report:   func(err error) { statuses = append(statuses, err) },
	}
	w.reconcileNativeState()
	if len(statuses) != 2 || statuses[0] == nil || statuses[1] == nil ||
		!reflect.DeepEqual(checks, []bool{true}) || !lost {
		t.Fatalf("failed recovery state: statuses=%v checks=%v lost=%v", statuses, checks, lost)
	}
	reject = false
	w.reconcileNativeState()
	if len(statuses) != 4 || statuses[2] == nil || statuses[3] != nil ||
		!reflect.DeepEqual(checks, []bool{true, true, false}) || lost {
		t.Fatalf("successful recovery state: statuses=%v checks=%v lost=%v", statuses, checks, lost)
	}
	if err := w.checkNativeState(); err != nil {
		t.Fatalf("recovered owned hook not healthy: %v", err)
	}
}

func TestNATNativeWrongHookUsesPreflightedOwnedTableReplacement(t *testing.T) {
	rules := ruleSet{MASQ: map[string]MASQRule{"n": {Subnet: "10.42.0.0/16", Bridge: "pst0"}}}
	wrongHook := true
	var scripts []string
	w := watcher{
		backend:     firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		applied:     rules,
		lastApplied: time.Now(),
		nftState: func() ([]byte, error) {
			return []byte(nftStateFixture(!wrongHook, 4)), nil
		},
		nftRules: func(script []byte, check bool) error {
			scripts = append(scripts, string(script))
			if !check {
				wrongHook = false
			}
			return nil
		},
		runRules: func(...string) error { return nil },
	}
	w.reconcileNativeState()
	if wrongHook || len(scripts) != 2 || scripts[0] != scripts[1] ||
		!strings.HasPrefix(scripts[0], "delete table ip "+nftNATTable+"\nadd table ip "+nftNATTable+"\n") {
		t.Fatalf("wrong-hook repair did not preflight and replace owned table: scripts=%v wrongHook=%v", scripts, wrongHook)
	}
	if err := w.checkNativeState(); err != nil {
		t.Fatalf("replaced owned hook not healthy: %v", err)
	}
}

func TestNATNativeWrongHookPreflightFailureDoesNotDeleteTable(t *testing.T) {
	rules := ruleSet{MASQ: map[string]MASQRule{"n": {Subnet: "10.42.0.0/16", Bridge: "pst0"}}}
	var calls []bool
	var reports []error
	w := watcher{
		backend:     firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		applied:     rules,
		lastApplied: time.Now(),
		nftState: func() ([]byte, error) {
			return []byte(nftStateFixture(false, 4)), nil
		},
		nftRules: func(script []byte, check bool) error {
			calls = append(calls, check)
			if !strings.HasPrefix(string(script), "delete table ip "+nftNATTable+"\n") {
				t.Fatal("replacement script did not limit deletion to the owned table")
			}
			return errors.New("preflight failed")
		},
		runRules: func(...string) error { t.Fatal("sysctl called after failed preflight"); return nil },
		report:   func(err error) { reports = append(reports, err) },
	}
	w.reconcileNativeState()
	if !reflect.DeepEqual(calls, []bool{true}) || len(reports) != 2 || reports[0] == nil || reports[1] == nil ||
		!reflect.DeepEqual(w.applied, rules) {
		t.Fatalf("failed replacement changed state: calls=%v reports=%v applied=%v", calls, reports, w.applied)
	}
}

func nftStateFixture(hook bool, rules int) string {
	chain := `{"chain":{"family":"ip","table":"pasturestack_hostnat","name":"postrouting","type":"nat","hook":"postrouting","prio":99,"policy":"accept"}}`
	if !hook {
		chain = `{"chain":{"family":"ip","table":"pasturestack_hostnat","name":"postrouting"}}`
	}
	entries := []string{chain}
	for i := 0; i < rules; i++ {
		entries = append(entries, `{"rule":{"family":"ip","table":"pasturestack_hostnat","chain":"postrouting"}}`)
	}
	return `{"nftables":[` + strings.Join(entries, ",") + `]}`
}

func TestNATNFTScriptPreservesLegacyRuleOrderAndOwnsOnlyItsTable(t *testing.T) {
	rules := ruleSet{
		MASQ: map[string]MASQRule{"z": {Subnet: "10.42.0.0/16", Bridge: "pst0"}},
		IKE:  map[string]IKEPortSNATRule{"a": {SourceIP: "10.42.0.2", HostIP: "192.0.2.2", Bridge: "pst0", Port: "500"}},
	}
	if err := validateNATRules(rules); err != nil {
		t.Fatal(err)
	}
	script := string(nftNATScript(rules))
	for _, want := range []string{
		"add table ip pasturestack_hostnat",
		"type nat hook postrouting priority 99; policy accept;",
		"flush chain ip pasturestack_hostnat postrouting",
		"ip saddr 10.42.0.2 udp sport 500 oifname != \"pst0\" snat to 192.0.2.2:500",
		"ip saddr 10.42.0.0/16 ip daddr != 10.42.0.0/16 oifname != \"pst0\" meta l4proto tcp masquerade to :1024-65535",
		"ip saddr 10.42.0.0/16 ip daddr != 10.42.0.0/16 oifname != \"pst0\" meta l4proto udp masquerade to :1024-65535",
		"ip saddr 10.42.0.0/16 ip daddr != 10.42.0.0/16 oifname != \"pst0\" masquerade",
		"oifname \"pst0\" fib saddr type local fib daddr type unicast masquerade",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script misses %q:\n%s", want, script)
		}
	}
	if strings.Index(script, "snat to") > strings.Index(script, "meta l4proto tcp") {
		t.Fatal("IKE SNAT must precede general MASQ")
	}
	if got := strings.Count(script, "ip daddr != 10.42.0.0/16"); got != 3 {
		t.Fatalf("all three general MASQ rules must exempt overlay destinations; got %d:\n%s", got, script)
	}
	for _, forbidden := range []string{"flush ruleset", "docker-bridges", "DOCKER-USER", "flush table"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("nft script must not touch Docker/global state: %s", forbidden)
		}
	}
}

func TestNATNFTPreflightFailureKeepsAppliedStateAndSkipsMutation(t *testing.T) {
	previous := ruleSet{MASQ: map[string]MASQRule{"old": {Subnet: "10.50.0.0/16", Bridge: "pst0"}}}
	rules := ruleSet{MASQ: map[string]MASQRule{"new": {Subnet: "10.42.0.0/16", Bridge: "pst0"}}}
	var calls []bool
	w := watcher{
		backend: firewall.Backend{Mode: firewall.NFTables, Command: "nft"},
		applied: previous,
		nftRules: func(script []byte, check bool) error {
			calls = append(calls, check)
			if !bytes.Contains(script, []byte("flush chain ip pasturestack_hostnat postrouting")) {
				t.Fatal("preflight did not receive full batch")
			}
			return errors.New("rejected")
		},
		runRules: func(...string) error { t.Fatal("sysctl/rule command called after failed preflight"); return nil },
	}
	if err := w.apply(rules); err == nil {
		t.Fatal("expected preflight error")
	}
	if !reflect.DeepEqual(calls, []bool{true}) || !reflect.DeepEqual(w.applied, previous) {
		t.Fatalf("failure changed state: calls=%v applied=%#v", calls, w.applied)
	}
}

func TestNATSelectedXTablesBackendDoesNotRemoveHookBeforeRestore(t *testing.T) {
	for _, tc := range []struct {
		mode    firewall.Mode
		cmd     string
		restore string
	}{
		{firewall.IptablesNFT, "iptables-nft", "iptables-nft-restore"},
		{firewall.IptablesLegacy, "iptables-legacy", "iptables-legacy-restore"},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			var checks []bool
			var commands [][]string
			w := watcher{
				backend: firewall.Backend{Mode: tc.mode, Command: tc.cmd, Restore: tc.restore},
				restoreRules: func(name string, script []byte, check bool) error {
					if name != tc.restore {
						t.Fatalf("used other backend: %s", name)
					}
					if !bytes.Contains(script, []byte("-F CATTLE_NAT_POSTROUTING")) {
						t.Fatal("restore does not update owned chain")
					}
					checks = append(checks, check)
					return nil
				},
				runRules: func(args ...string) error {
					commands = append(commands, args)
					return nil
				},
			}
			if err := w.apply(ruleSet{}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(checks, []bool{true, false}) {
				t.Fatalf("restore preflight/apply sequence=%v", checks)
			}
			if len(commands) != 1 || !reflect.DeepEqual(commands[0], []string{tc.cmd, "-w", "-t", "nat", "-C", "POSTROUTING", "-j", natChain}) {
				t.Fatalf("unexpected hook operations: %#v", commands)
			}
		})
	}
}
