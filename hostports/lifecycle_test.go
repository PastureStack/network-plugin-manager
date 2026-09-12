package hostports

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/firewall"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
)

type emptyHostportMetadata struct{ metadata.Client }

func (emptyHostportMetadata) GetNetworks() ([]metadata.Network, error)     { return nil, nil }
func (emptyHostportMetadata) GetContainers() ([]metadata.Container, error) { return nil, nil }

func emptyHostportWatcher() *watcher {
	return &watcher{
		c: emptyHostportMetadata{},
		localHost: func(metadata.Client, *client.Client) (metadata.Host, error) {
			return metadata.Host{UUID: "host-1"}, nil
		},
		applied:     ruleSet{Ports: map[string]PortRule{}, ForwardSubnets: map[string]string{}},
		lastApplied: time.Now(),
	}
}

const intactEmptyNFT = `{"nftables":[
 {"table":{"family":"ip","name":"pasturestack_hostports"}},
 {"chain":{"family":"ip","table":"pasturestack_hostports","name":"prerouting","type":"nat","hook":"prerouting","prio":-101,"policy":"accept"}},
 {"chain":{"family":"ip","table":"pasturestack_hostports","name":"output","type":"nat","hook":"output","prio":-101,"policy":"accept"}},
 {"chain":{"family":"ip","table":"pasturestack_hostports","name":"postrouting","type":"nat","hook":"postrouting","prio":99,"policy":"accept"}},
 {"chain":{"family":"ip","table":"pasturestack_hostports","name":"forward","type":"filter","hook":"forward","prio":-1,"policy":"accept"}},
 {"rule":{"family":"ip","table":"pasturestack_hostports","chain":"forward"}},
 {"rule":{"family":"ip","table":"pasturestack_hostports","chain":"forward"}}
]}`

func TestNativePeriodicRepairRestoresMissingTableAndReadiness(t *testing.T) {
	w := emptyHostportWatcher()
	w.backend = firewall.Backend{Mode: firewall.NFTables, Command: "nft"}
	installed := false
	var reports []error
	w.report = func(err error) { reports = append(reports, err) }
	w.output = func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "nft -j list table ip pasturestack_hostports":
			if installed {
				return []byte(intactEmptyNFT), nil
			}
			return nil, errors.New("table does not exist")
		case "nft list tables":
			if installed {
				return []byte("table ip pasturestack_hostports\n"), nil
			}
			return nil, nil
		default:
			t.Fatalf("unexpected command: %v", args)
			return nil, nil
		}
	}
	var checks, applies int
	w.restoreRules = func(_ string, args []string, _ []byte) error {
		switch strings.Join(args, " ") {
		case "-c -f -":
			checks++
		case "-f -":
			applies++
			installed = true
		default:
			t.Fatalf("unexpected restore flags: %v", args)
		}
		return nil
	}
	if err := w.repairOnce(); err != nil {
		t.Fatal(err)
	}
	if checks != 1 || applies != 1 || len(reports) != 2 || reports[0] == nil || reports[1] != nil {
		t.Fatalf("missing-table repair: checks=%d applies=%d reports=%v", checks, applies, reports)
	}
	if err := w.repairOnce(); err != nil {
		t.Fatal(err)
	}
	if checks != 1 || applies != 1 || len(reports) != 3 || reports[2] != nil {
		t.Fatalf("healthy periodic pass unnecessarily re-applied: checks=%d applies=%d reports=%v", checks, applies, reports)
	}
}

func TestNativePeriodicRepairDetectsFlushedRules(t *testing.T) {
	w := emptyHostportWatcher()
	w.backend = firewall.Backend{Mode: firewall.NFTables, Command: "nft"}
	w.output = func(args ...string) ([]byte, error) {
		if reflect.DeepEqual(args, []string{"nft", "list", "tables"}) {
			return []byte("table ip pasturestack_hostports\n"), nil
		}
		return []byte(strings.ReplaceAll(intactEmptyNFT,
			`{"rule":{"family":"ip","table":"pasturestack_hostports","chain":"forward"}},`, "")), nil
	}
	var reports []error
	w.report = func(err error) { reports = append(reports, err) }
	var applies int
	w.restoreRules = func(_ string, args []string, _ []byte) error {
		if reflect.DeepEqual(args, []string{"-f", "-"}) {
			applies++
		}
		return nil
	}
	if err := w.repairOnce(); err != nil {
		t.Fatal(err)
	}
	if applies != 1 || len(reports) != 2 || reports[0] == nil || reports[1] != nil {
		t.Fatalf("flushed nft rules were not reported and repaired: applies=%d reports=%v", applies, reports)
	}
}

func TestNativePeriodicRepairDetectsMissingHookAndFailedRebuild(t *testing.T) {
	w := emptyHostportWatcher()
	w.backend = firewall.Backend{Mode: firewall.NFTables, Command: "nft"}
	w.output = func(args ...string) ([]byte, error) {
		if reflect.DeepEqual(args, []string{"nft", "list", "tables"}) {
			return []byte("table ip pasturestack_hostports\n"), nil
		}
		return []byte(strings.Replace(intactEmptyNFT, `"hook":"forward"`, `"hook":"input"`, 1)), nil
	}
	w.restoreRules = func(_ string, args []string, _ []byte) error {
		if reflect.DeepEqual(args, []string{"-c", "-f", "-"}) {
			return errors.New("nft preflight rejected batch")
		}
		t.Fatal("a failed preflight must not apply the batch")
		return nil
	}
	var reports []error
	w.report = func(err error) { reports = append(reports, err) }
	if err := w.repairOnce(); err == nil {
		t.Fatal("expected failed rebuild")
	}
	if len(reports) != 2 || reports[0] == nil || reports[1] == nil || !strings.Contains(reports[0].Error(), "unexpected hook") {
		t.Fatalf("missing hook or failed rebuild incorrectly marked healthy: %v", reports)
	}
}

func TestLegacyPeriodicRepairFailureRevokesReadiness(t *testing.T) {
	w := emptyHostportWatcher()
	w.backend = firewall.Backend{Mode: firewall.IptablesNFT, Command: "iptables-nft", Restore: "iptables-nft-restore"}
	w.runCommand = func(args ...string) error { return errors.New("iptables unavailable") }
	w.output = func(args ...string) ([]byte, error) { return nil, errors.New("iptables unavailable") }
	w.restoreRules = func(_ string, _ []string, _ []byte) error { return errors.New("restore unavailable") }
	var reports []error
	w.report = func(err error) { reports = append(reports, err) }
	if err := w.repairOnce(); err == nil {
		t.Fatal("expected failed base-hook repair to leave watcher unhealthy")
	}
	if len(reports) < 2 || reports[0] == nil || reports[len(reports)-1] == nil {
		t.Fatalf("base-hook repair failure was suppressed: %v", reports)
	}
}

func TestPeriodicAndMetadataReconcilesAreSerialized(t *testing.T) {
	w := emptyHostportWatcher()
	w.backend = firewall.Backend{Mode: firewall.NFTables, Command: "nft"}
	var mu sync.Mutex
	active := 0
	maxActive := 0
	w.localHost = func(metadata.Client, *client.Client) (metadata.Host, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		return metadata.Host{UUID: "host-1"}, nil
	}
	w.output = func(args ...string) ([]byte, error) { return []byte(intactEmptyNFT), nil }
	w.report = func(err error) {
		if err != nil {
			t.Error(fmt.Errorf("unexpected report: %w", err))
		}
	}
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); w.onChangeNoError("metadata") }()
	go func() { defer group.Done(); _ = w.repairOnce() }()
	group.Wait()
	if maxActive != 1 {
		t.Fatalf("metadata and periodic reconcile overlapped: %d", maxActive)
	}
}
