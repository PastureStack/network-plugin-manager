package firewall

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

func TestResolveSelectsOnlyOneBackend(t *testing.T) {
	lookup := func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	versions := func(name string) (string, error) {
		if strings.Contains(name, "legacy") {
			return "iptables v1.8.11 (legacy)", nil
		}
		return "iptables v1.8.11 (nf_tables)", nil
	}
	for _, tc := range []struct {
		name, docker string
		requested    Mode
		want         Mode
	}{
		{"modern observed frontend", "iptables", IptablesNFT, IptablesNFT},
		{"old observed frontend", "iptables", IptablesLegacy, IptablesLegacy},
		{"Docker native", "nftables", Auto, NFTables},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Resolve(tc.requested, tc.docker, lookup, versions)
			if err != nil || b.Mode != tc.want {
				t.Fatalf("Resolve() = %+v, %v, want %s", b, err, tc.want)
			}
		})
	}
}

func TestResolveDoesNotInferDockerFrontendFromContainerAlternative(t *testing.T) {
	lookup := func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	versions := func(string) (string, error) { return "iptables v1.8.11 (nf_tables)", nil }
	if _, err := Resolve(Auto, "iptables", lookup, versions); err == nil {
		t.Fatal("auto mode inferred Docker's frontend from the manager container's iptables alternative")
	}
}

// Run only inside a disposable VM with a real Docker socket. This confirms
// Docker's reported backend and our executable selection agree on that host.
func TestDetectOnDisposableVM(t *testing.T) {
	if os.Getenv("PASTURESTACK_FIREWALL_VM_TEST") != "1" {
		t.Skip("opt-in disposable VM integration test")
	}
	dc, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Detect(dc, Auto)
	if err != nil {
		t.Fatal(err)
	}
	want := Mode(os.Getenv("PASTURESTACK_EXPECT_FIREWALL_MODE"))
	if got.Mode != want || want == "" {
		t.Fatalf("selected %s (command=%s), want %s", got.Mode, got.Command, want)
	}
}

func TestResolveDoesNotSilentlyDowngrade(t *testing.T) {
	lookup := func(name string) (string, error) {
		if name == "nft" || strings.Contains(name, "nft") {
			return "", errors.New("missing")
		}
		return "/usr/sbin/" + name, nil
	}
	versions := func(string) (string, error) { return "iptables v1.8.11 (legacy)", nil }
	if _, err := Resolve(IptablesNFT, "iptables", lookup, versions); err == nil {
		t.Fatal("missing nft frontend silently downgraded")
	}
	if _, err := Resolve(NFTables, "iptables", lookup, versions); err == nil {
		t.Fatal("native nftables accepted Docker's iptables firewall backend")
	}
	if _, err := Resolve(IptablesLegacy, "nftables", lookup, versions); err == nil {
		t.Fatal("legacy frontend accepted Docker native nftables")
	}
}

func TestNativeMigrationRejectsStaleRulesWithoutChangingThem(t *testing.T) {
	lookup := func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	for _, tc := range []struct {
		name, filter, nat string
		wantError         bool
	}{
		{"fresh native", "-P FORWARD ACCEPT\n-A FORWARD -j DOCKER-USER\n", "-A PREROUTING -j DOCKER\n", false},
		{"stale global drop", "-P FORWARD DROP\n", "", true},
		{"stale platform hook", "-P FORWARD ACCEPT\n", "-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspect := func(_ string, args ...string) ([]byte, error) {
				if len(args) > 1 && args[1] == "filter" {
					return []byte(tc.filter), nil
				}
				return []byte(tc.nat), nil
			}
			err := CheckNativeMigration(lookup, inspect)
			if (err != nil) != tc.wantError {
				t.Fatalf("CheckNativeMigration() error = %v, want error=%t", err, tc.wantError)
			}
		})
	}
}

func TestDockerBridgeMarkMustBeInstalled(t *testing.T) {
	for _, tc := range []struct {
		name, rules string
		wantError   bool
	}{
		{"configured", `meta mark & 0x00001068 == 0x00001068 counter packets 0 bytes 0 accept`, false},
		{"not configured", `meta mark & 0x00001000 == 0x00001000 accept`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspect := func(_ string, _ ...string) ([]byte, error) { return []byte(tc.rules), nil }
			err := CheckDockerBridgeMark(inspect)
			if (err != nil) != tc.wantError {
				t.Fatalf("CheckDockerBridgeMark() error = %v, want error=%t", err, tc.wantError)
			}
		})
	}
}

func TestDetectDockerXTFrontendUsesDockerChainsWithoutLegacyAutoload(t *testing.T) {
	const dockerNAT = "-N DOCKER\n-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n"
	lookup := func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	versions := func(name string) (string, error) {
		if name == "iptables-legacy" {
			return "iptables v1.8.11 (legacy)", nil
		}
		return "iptables v1.8.11 (nf_tables)", nil
	}
	for _, tc := range []struct {
		name, nft, legacy, tables string
		want                      Mode
		wantErr                   bool
		legacyProbes              int
	}{
		{"nft only does not probe unloaded legacy", dockerNAT, "", "", IptablesNFT, false, 0},
		{"legacy only", "-N OTHER\n", dockerNAT, "filter\nnat\n", IptablesLegacy, false, 1},
		{"both Docker chains fail closed", dockerNAT, dockerNAT, "nat\n", "", true, 1},
		{"neither Docker chain fails closed", "-N OTHER\n", "-N OTHER\n", "nat\n", "", true, 1},
		{"legacy table without nat is not probed", dockerNAT, dockerNAT, "filter\n", IptablesNFT, false, 0},
		{"unhooked stale legacy chain does not count", dockerNAT, "-N DOCKER\n", "nat\n", IptablesNFT, false, 1},
		{"old platform hook without legacy Docker is inspected but not selected", dockerNAT, "-N CATTLE_NAT_POSTROUTING\n-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "nat\n", IptablesNFT, false, 1},
		{"old platform hook cannot hide a second Docker backend", dockerNAT, dockerNAT + "-N CATTLE_NAT_POSTROUTING\n-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "nat\n", "", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacyProbes := 0
			inspect := func(name string, args ...string) ([]byte, error) {
				if strings.Contains(name, "legacy") {
					legacyProbes++
					return []byte(tc.legacy), nil
				}
				if name != "iptables-nft" || strings.Join(args, " ") != "-t nat -S" {
					t.Fatalf("unexpected inspection: %s %v", name, args)
				}
				return []byte(tc.nft), nil
			}
			readFile := func(name string) ([]byte, error) {
				if name != "/proc/net/ip_tables_names" {
					t.Fatalf("unexpected read: %s", name)
				}
				return []byte(tc.tables), nil
			}
			got, err := DetectDockerXTFrontend(lookup, versions, inspect, readFile)
			if got != tc.want || (err != nil) != tc.wantErr || legacyProbes != tc.legacyProbes {
				t.Fatalf("frontend=%q error=%v legacyProbes=%d; want %q error=%t legacyProbes=%d", got, err, legacyProbes, tc.want, tc.wantErr, tc.legacyProbes)
			}
		})
	}
}

func TestDetectDockerXTFrontendFailsClosedWhenLegacyCannotBeInspected(t *testing.T) {
	for _, tc := range []struct {
		name, legacyVersion string
		legacyExists        bool
	}{
		{"dedicated binary missing", "", false},
		{"dedicated binary points to nft", "iptables v1.8.11 (nf_tables)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, error) {
				if name == "iptables-legacy" && !tc.legacyExists {
					return "", os.ErrNotExist
				}
				return "/usr/sbin/" + name, nil
			}
			versions := func(name string) (string, error) {
				if name == "iptables-legacy" {
					return tc.legacyVersion, nil
				}
				return "iptables v1.8.11 (nf_tables)", nil
			}
			inspect := func(name string, _ ...string) ([]byte, error) {
				if name == "iptables" || name == "iptables-legacy" {
					t.Fatalf("inspected legacy rules through an unverified frontend: %s", name)
				}
				return []byte("-N DOCKER\n-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n"), nil
			}
			readFile := func(string) ([]byte, error) { return []byte("nat\n"), nil }
			if _, err := DetectDockerXTFrontend(lookup, versions, inspect, readFile); err == nil {
				t.Fatal("selected nft even though a loaded legacy NAT table could not be inspected")
			}
		})
	}
}

func TestDetectDockerXTFrontendAllowsVerifiedLegacyWhenNFTUnavailable(t *testing.T) {
	legacyNAT := []byte("-N DOCKER\n-A OUTPUT -m addrtype --dst-type LOCAL -j DOCKER\n")
	for _, tc := range []struct {
		name      string
		nftExists bool
		nftOutput string
		nftErr    error
	}{
		{"old host without nft command", false, "", nil},
		{"old kernel rejects nft protocol", true, "iptables-nft: Protocol not supported", errors.New("exit status 1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, error) {
				if name == "iptables-nft" && !tc.nftExists {
					return "", os.ErrNotExist
				}
				return "/usr/sbin/" + name, nil
			}
			versions := func(name string) (string, error) {
				if name == "iptables-nft" {
					return "iptables v1.8.11 (nf_tables)", nil
				}
				return "iptables v1.8.11 (legacy)", nil
			}
			inspect := func(name string, _ ...string) ([]byte, error) {
				if name == "iptables-legacy" {
					return legacyNAT, nil
				}
				if name == "iptables-nft" {
					return []byte(tc.nftOutput), tc.nftErr
				}
				t.Fatalf("unexpected inspection of %s", name)
				return nil, nil
			}
			readFile := func(string) ([]byte, error) { return []byte("nat\n"), nil }
			got, err := DetectDockerXTFrontend(lookup, versions, inspect, readFile)
			if err != nil || got != IptablesLegacy {
				t.Fatalf("frontend=%q, error=%v; want verified legacy", got, err)
			}
		})
	}
}

func TestDetectDockerXTFrontendDoesNotMaskNFTInspectionErrors(t *testing.T) {
	lookup := func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	versions := func(name string) (string, error) {
		if name == "iptables-legacy" {
			return "iptables v1.8.11 (legacy)", nil
		}
		return "iptables v1.8.11 (nf_tables)", nil
	}
	legacyCalls := 0
	inspect := func(name string, _ ...string) ([]byte, error) {
		if name == "iptables-legacy" {
			legacyCalls++
			return []byte("-N DOCKER\n-A PREROUTING -j DOCKER\n"), nil
		}
		return []byte("Permission denied"), errors.New("exit status 1")
	}
	readFile := func(string) ([]byte, error) { return []byte("nat\n"), nil }
	if _, err := DetectDockerXTFrontend(lookup, versions, inspect, readFile); err == nil {
		t.Fatal("permission failure silently selected legacy")
	}
	if legacyCalls != 0 {
		t.Fatalf("probed legacy after an unsafe nft inspection failure: %d calls", legacyCalls)
	}
}

func TestExplicitDockerXTModeMustMatchObservedChain(t *testing.T) {
	for _, tc := range []struct {
		requested, active, want Mode
		wantErr                 bool
	}{
		{Auto, IptablesNFT, IptablesNFT, false},
		{"", IptablesLegacy, IptablesLegacy, false},
		{IptablesLegacy, IptablesLegacy, IptablesLegacy, false},
		{IptablesLegacy, IptablesNFT, "", true},
		{IptablesNFT, IptablesLegacy, "", true},
	} {
		got, err := SelectDockerXTMode(tc.requested, tc.active)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("SelectDockerXTMode(%q, %q) = %q, %v; want %q, error=%t", tc.requested, tc.active, got, err, tc.want, tc.wantErr)
		}
	}
}
