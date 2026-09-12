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

func TestDockerFirewallDriverRequiresReportFromDocker29(t *testing.T) {
	for _, tc := range []struct {
		name, reported, version, want string
		wantError                     bool
	}{
		{"Docker 29 native reported", "nftables", "29.8.0", "nftables", false},
		{"Docker 29 iptables reported", "iptables", "29.8.0", "iptables", false},
		{"Docker 29 missing report", "", "29.8.0", "", true},
		{"future Docker missing report", "", "30.0.0", "", true},
		{"old Docker missing report", "", "24.0.9", "iptables", false},
		{"unparseable version missing report", "", "unknown", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dockerFirewallDriver(tc.reported, tc.version)
			if got != tc.want || (err != nil) != tc.wantError {
				t.Fatalf("dockerFirewallDriver(%q, %q) = %q, %v; want %q, error=%t", tc.reported, tc.version, got, err, tc.want, tc.wantError)
			}
		})
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
	version := func(name string) (string, error) {
		if name == "iptables-legacy" {
			return "iptables v1.8.11 (legacy)", nil
		}
		return "iptables v1.8.11 (nf_tables)", nil
	}
	for _, tc := range []struct {
		name, nftFilter, nftNAT, legacyFilter, legacyNAT, loaded string
		wantError                                                bool
		legacyProbes                                             int
	}{
		{"fresh native does not load legacy", "-P FORWARD ACCEPT\n", "", "", "", "", false, 0},
		{"stale nft global drop", "-P FORWARD DROP\n", "", "", "", "", true, 0},
		{"stale nft platform hook", "", "-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "", "", "", true, 0},
		{"loaded legacy NAT platform hook", "", "", "", "-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "nat\n", true, 1},
		{"loaded legacy filter platform hook", "", "", "-A FORWARD -g CATTLE_FORWARD\n", "", "filter\n", true, 1},
		{"loaded legacy long-form jump", "", "", "-A FORWARD --goto CATTLE_FORWARD\n", "", "filter\n", true, 1},
		{"loaded legacy Docker NAT hook", "", "", "", "-N DOCKER\n-A PREROUTING -j DOCKER\n", "nat\n", true, 1},
		{"loaded legacy global drop", "", "", "-P FORWARD DROP\n", "", "filter\n", true, 1},
		{"loaded unhooked legacy chains", "", "", "-N CATTLE_FORWARD\n", "-N DOCKER\n", "filter\nnat\n", false, 2},
		{"loaded orphaned legacy chain jump", "", "", "-N OLD\n-N CATTLE_FORWARD\n-A OLD -j CATTLE_FORWARD\n", "", "filter\n", false, 1},
		{"loaded indirect legacy platform hook", "", "", "-N OLD\n-A FORWARD -j OLD\n-A OLD -j CATTLE_FORWARD\n", "", "filter\n", true, 1},
		{"loaded unrelated legacy rules", "", "", "-P FORWARD ACCEPT\n-A FORWARD -j OTHER\n", "", "filter\n", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacyProbes := 0
			inspect := func(name string, args ...string) ([]byte, error) {
				if len(args) != 3 || args[0] != "-t" || args[2] != "-S" {
					t.Fatalf("unexpected inspection: %s %v", name, args)
				}
				if name == "iptables-legacy" {
					legacyProbes++
					if args[1] == "filter" {
						return []byte(tc.legacyFilter), nil
					}
					return []byte(tc.legacyNAT), nil
				}
				if name != "iptables-nft" {
					t.Fatalf("unexpected frontend: %s", name)
				}
				if args[1] == "filter" {
					return []byte(tc.nftFilter), nil
				}
				return []byte(tc.nftNAT), nil
			}
			readFile := func(path string) ([]byte, error) {
				if path != "/proc/net/ip_tables_names" {
					t.Fatalf("unexpected read: %s", path)
				}
				return []byte(tc.loaded), nil
			}
			err := CheckNativeMigration(lookup, version, inspect, readFile)
			if (err != nil) != tc.wantError || legacyProbes != tc.legacyProbes {
				t.Fatalf("CheckNativeMigration() error = %v, legacyProbes=%d; want error=%t, legacyProbes=%d", err, legacyProbes, tc.wantError, tc.legacyProbes)
			}
		})
	}
}

func TestNativeMigrationAllowsAbsentLegacyProcFile(t *testing.T) {
	lookup := func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	version := func(string) (string, error) { return "iptables v1.8.11 (nf_tables)", nil }
	legacyProbes := 0
	inspect := func(name string, _ ...string) ([]byte, error) {
		if name == "iptables-legacy" {
			legacyProbes++
		}
		return []byte("-P FORWARD ACCEPT\n"), nil
	}
	readFile := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if err := CheckNativeMigration(lookup, version, inspect, readFile); err != nil || legacyProbes != 0 {
		t.Fatalf("clean native host rejected or legacy probed: error=%v, probes=%d", err, legacyProbes)
	}
}

func TestNativeMigrationFailsClosedWhenLoadedLegacyCannotBeChecked(t *testing.T) {
	for _, tc := range []struct {
		name, tables, legacyVersion string
		legacyExists, inspectFails  bool
	}{
		{"dedicated binary missing", "nat\n", "", false, false},
		{"dedicated binary points to nft", "filter\n", "iptables v1.8.11 (nf_tables)", true, false},
		{"loaded table inspection fails", "nat\n", "iptables v1.8.11 (legacy)", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, error) {
				if name == "iptables-legacy" && !tc.legacyExists {
					return "", os.ErrNotExist
				}
				return "/usr/sbin/" + name, nil
			}
			version := func(name string) (string, error) {
				if name == "iptables-legacy" {
					return tc.legacyVersion, nil
				}
				return "iptables v1.8.11 (nf_tables)", nil
			}
			inspect := func(name string, _ ...string) ([]byte, error) {
				if name == "iptables-legacy" && tc.inspectFails {
					return nil, errors.New("inspection refused")
				}
				return nil, nil
			}
			readFile := func(string) ([]byte, error) { return []byte(tc.tables), nil }
			if err := CheckNativeMigration(lookup, version, inspect, readFile); err == nil {
				t.Fatal("native mode started despite uninspectable loaded legacy table")
			}
		})
	}
	lookup := func(string) (string, error) { return "/usr/sbin/iptables-nft", nil }
	version := func(string) (string, error) { return "iptables v1.8.11 (legacy)", nil }
	inspect := func(string, ...string) ([]byte, error) { return nil, nil }
	readFile := func(string) ([]byte, error) { return nil, errors.New("proc unavailable") }
	if err := CheckNativeMigration(lookup, version, inspect, readFile); err == nil {
		t.Fatal("native mode started without knowing whether legacy tables were loaded")
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
		name, nft, legacy, nftFilter, legacyFilter, tables string
		want                                               Mode
		wantErr                                            bool
		legacyProbes                                       int
	}{
		{"nft only does not probe unloaded legacy", dockerNAT, "", "", "", "", IptablesNFT, false, 0},
		{"legacy only", "-N OTHER\n", dockerNAT, "", "", "filter\nnat\n", IptablesLegacy, false, 1},
		{"both Docker chains fail closed", dockerNAT, dockerNAT, "", "", "nat\n", "", true, 1},
		{"neither Docker chain fails closed", "-N OTHER\n", "-N OTHER\n", "", "", "nat\n", "", true, 1},
		{"loaded legacy filter without hooks is inspected", dockerNAT, "", "", "-P FORWARD ACCEPT\n", "filter\n", IptablesNFT, false, 1},
		{"unhooked stale legacy chain does not count", dockerNAT, "-N DOCKER\n-N CATTLE_NAT_POSTROUTING\n", "", "", "nat\n", IptablesNFT, false, 1},
		{"opposite legacy NAT platform hook fails closed", dockerNAT, "-N CATTLE_NAT_POSTROUTING\n-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "", "", "nat\n", "", true, 1},
		{"opposite legacy filter platform hook fails closed", dockerNAT, "", "", "-A FORWARD -g CATTLE_FORWARD\n", "filter\n", "", true, 1},
		{"opposite nft NAT platform hook fails closed", "-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", dockerNAT, "", "", "nat\n", "", true, 1},
		{"opposite nft filter platform hook fails closed", "", dockerNAT, "-A FORWARD -j CATTLE_FORWARD\n", "", "nat\n", "", true, 1},
		{"selected nft platform hook remains allowed", dockerNAT + "-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "", "", "", "", IptablesNFT, false, 0},
		{"selected legacy platform hook remains allowed", "", dockerNAT + "-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "", "", "nat\n", IptablesLegacy, false, 1},
		{"old platform hook cannot hide a second Docker backend", dockerNAT, dockerNAT + "-N CATTLE_NAT_POSTROUTING\n-A POSTROUTING -j CATTLE_NAT_POSTROUTING\n", "", "", "nat\n", "", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacyProbes := 0
			inspect := func(name string, args ...string) ([]byte, error) {
				if strings.Contains(name, "legacy") {
					legacyProbes++
					if strings.Join(args, " ") == "-t filter -S" {
						return []byte(tc.legacyFilter), nil
					}
					return []byte(tc.legacy), nil
				}
				if name != "iptables-nft" {
					t.Fatalf("unexpected inspection: %s %v", name, args)
				}
				if strings.Join(args, " ") == "-t filter -S" {
					return []byte(tc.nftFilter), nil
				}
				if strings.Join(args, " ") != "-t nat -S" {
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
