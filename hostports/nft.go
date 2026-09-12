package hostports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const nftHostportsTable = "pasturestack_hostports"

// checkNFTRules checks only the table this watcher owns. Docker can remove
// external nft chains on restart without a metadata event; counting our rules
// also detects a flushed base chain while the table itself still exists.
func (w *watcher) checkNFTRules() error {
	out, err := w.commandOutput("nft", "-j", "list", "table", "ip", nftHostportsTable)
	if err != nil {
		return fmt.Errorf("inspect native nft hostport table: %w", err)
	}
	var listing struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &listing); err != nil {
		return fmt.Errorf("decode native nft hostport table: %w", err)
	}
	type chain struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Hook   string `json:"hook"`
		Prio   int    `json:"prio"`
		Policy string `json:"policy"`
	}
	expected := map[string]chain{
		"prerouting":  {Type: "nat", Hook: "prerouting", Prio: -101, Policy: "accept"},
		"output":      {Type: "nat", Hook: "output", Prio: -101, Policy: "accept"},
		"postrouting": {Type: "nat", Hook: "postrouting", Prio: 99, Policy: "accept"},
		"forward":     {Type: "filter", Hook: "forward", Prio: -1, Policy: "accept"},
	}
	ruleCount := map[string]int{}
	for _, p := range w.applied.Ports {
		ruleCount["prerouting"]++
		if p.Bridge != "" {
			ruleCount["prerouting"]++
			ruleCount["postrouting"]++
		}
		ruleCount["output"]++
		ruleCount["postrouting"]++
	}
	ruleCount["forward"] = 2 + len(sortedForwardSubnets(w.applied.ForwardSubnets))
	seen := map[string]bool{}
	actualRules := map[string]int{}
	for _, item := range listing.NFTables {
		if raw, ok := item["chain"]; ok {
			var got chain
			if err := json.Unmarshal(raw, &got); err != nil {
				return fmt.Errorf("decode native nft hostport chain: %w", err)
			}
			want, required := expected[got.Name]
			if required {
				if got.Family != "ip" || got.Table != nftHostportsTable || got.Type != want.Type || got.Hook != want.Hook || got.Prio != want.Prio || got.Policy != want.Policy {
					return fmt.Errorf("native nft hostport chain %q has unexpected hook or policy", got.Name)
				}
				seen[got.Name] = true
			}
		}
		if raw, ok := item["rule"]; ok {
			var got struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Chain  string `json:"chain"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				return fmt.Errorf("decode native nft hostport rule: %w", err)
			}
			if got.Family == "ip" && got.Table == nftHostportsTable {
				actualRules[got.Chain]++
			}
		}
	}
	for name := range expected {
		if !seen[name] || actualRules[name] != ruleCount[name] {
			return fmt.Errorf("native nft hostport chain %q is missing or has %d rules, want %d", name, actualRules[name], ruleCount[name])
		}
	}
	return nil
}

// applyNFT replaces only the table owned by this watcher. The check and apply
// commands use the same complete batch; nft applies a batch transactionally.
// Docker's native nftables tables and the host's FORWARD policy are untouched.
func (w *watcher) applyNFT(rules ruleSet) error {
	out, err := w.commandOutput("nft", "list", "tables")
	if err != nil {
		return fmt.Errorf("inspect nft tables before hostport update: %w", err)
	}
	exists := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == "ip" && fields[2] == nftHostportsTable {
			exists = true
			break
		}
	}
	batch := nftHostportBatch(rules, exists)
	if err := w.restore("nft", []string{"-c", "-f", "-"}, batch); err != nil {
		return fmt.Errorf("validate native nft hostport batch: %w", err)
	}
	if err := w.restore("nft", []string{"-f", "-"}, batch); err != nil {
		return fmt.Errorf("apply native nft hostport batch: %w", err)
	}
	w.applied = rules
	w.lastApplied = time.Now()
	return nil
}

func nftHostportBatch(rules ruleSet, existing bool) []byte {
	buf := &bytes.Buffer{}
	if existing {
		fmt.Fprintf(buf, "delete table ip %s\n", nftHostportsTable)
	}
	fmt.Fprintf(buf, "table ip %s {\n", nftHostportsTable)
	buf.WriteString(" chain prerouting {\n  type nat hook prerouting priority -101; policy accept;\n")
	keys := make([]string, 0, len(rules.Ports))
	for key := range rules.Ports {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := rules.Ports[key]
		condition := nftPortMatch(p)
		if p.Bridge != "" {
			fmt.Fprintf(buf, "  %s iifname != %q meta mark set meta mark | 0x1068 dnat to %s:%s\n", condition, p.Bridge, p.TargetIP, p.TargetPort)
			fmt.Fprintf(buf, "  %s iifname %q meta mark set meta mark | 0x1068 dnat to %s:%s\n", condition, p.Bridge, p.TargetIP, p.TargetPort)
		} else {
			fmt.Fprintf(buf, "  %s meta mark set meta mark | 0x1068 dnat to %s:%s\n", condition, p.TargetIP, p.TargetPort)
		}
	}
	buf.WriteString(" }\n chain output {\n  type nat hook output priority -101; policy accept;\n")
	for _, key := range keys {
		p := rules.Ports[key]
		match := "fib daddr type local"
		if p.SourceIP != "0.0.0.0" {
			match += " ip daddr " + p.SourceIP
		}
		fmt.Fprintf(buf, "  %s %s dport %s dnat to %s:%s\n", match, p.Protocol, p.SourcePort, p.TargetIP, p.TargetPort)
	}
	buf.WriteString(" }\n chain postrouting {\n  type nat hook postrouting priority 99; policy accept;\n")
	for _, key := range keys {
		p := rules.Ports[key]
		if p.Bridge != "" {
			// A peer on the same bridge reaching the host address must receive
			// its reply through conntrack, not directly across the bridge.
			fmt.Fprintf(buf, "  iifname %q oifname %q ip daddr %s %s dport %s masquerade\n", p.Bridge, p.Bridge, p.TargetIP, p.Protocol, p.TargetPort)
		}
		fmt.Fprintf(buf, "  ip saddr %s ip daddr %s %s dport %s masquerade\n", p.TargetIP, p.TargetIP, p.Protocol, p.TargetPort)
	}
	buf.WriteString(" }\n chain forward {\n  type filter hook forward priority -1; policy accept;\n")
	for _, subnet := range sortedForwardSubnets(rules.ForwardSubnets) {
		fmt.Fprintf(buf, "  ip saddr %s ip daddr %s meta mark set meta mark | 0x1068 accept\n", subnet, subnet)
	}
	// An accept verdict here is NOT a final accept through Docker's native
	// bridge filter chains. Docker must be configured to recognize mark 0x1068
	// with bridge-accept-fwmark, and reachability must be tested end-to-end.
	buf.WriteString("  meta mark & 0x1068 == 0x1068 accept\n  meta mark 0x4000 accept\n }\n}\n")
	return buf.Bytes()
}

func nftPortMatch(p PortRule) string {
	condition := "fib daddr type local"
	if p.SourceIP != "0.0.0.0" {
		condition += " ip daddr " + p.SourceIP
	}
	return fmt.Sprintf("%s %s dport %s", condition, p.Protocol, p.SourcePort)
}
