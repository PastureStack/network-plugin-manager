package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/moby/moby/client"
)

// Mode names the *single* host firewall implementation used by this process.
// iptables-nft is the xtables compatibility CLI; nftables is Docker's native
// firewall backend and uses nft directly. They are not interchangeable.
type Mode string

const (
	Auto           Mode = "auto"
	IptablesNFT    Mode = "iptables-nft"
	IptablesLegacy Mode = "iptables-legacy"
	NFTables       Mode = "nftables"
)

type Backend struct {
	Mode    Mode
	Command string
	Restore string
}

// Detect resolves the backend once, before either rule watcher starts. An
// available legacy executable is never evidence that legacy should be used.
func Detect(dc *client.Client, requested Mode) (Backend, error) {
	info, err := dc.Info(context.Background(), client.InfoOptions{})
	if err != nil {
		return Backend{}, fmt.Errorf("read Docker firewall backend: %w", err)
	}
	reportedDriver := ""
	if info.Info.FirewallBackend != nil && info.Info.FirewallBackend.Driver != "" {
		reportedDriver = info.Info.FirewallBackend.Driver
	}
	driver, err := dockerFirewallDriver(reportedDriver, info.Info.ServerVersion)
	if err != nil {
		return Backend{}, err
	}
	if driver == "iptables" {
		// The manager container's iptables alternative need not match the host
		// daemon's. Observe Docker's live NAT chain before selecting a frontend.
		active, err := DetectDockerXTFrontend(exec.LookPath, commandVersion, inspectRules, os.ReadFile)
		if err != nil {
			return Backend{}, err
		}
		requested, err = SelectDockerXTMode(requested, active)
		if err != nil {
			return Backend{}, err
		}
	}
	backend, err := Resolve(requested, driver, exec.LookPath, commandVersion)
	if err != nil {
		return Backend{}, err
	}
	if backend.Mode == NFTables {
		if err := CheckNativeMigration(exec.LookPath, commandVersion, inspectRules, os.ReadFile); err != nil {
			return Backend{}, err
		}
		if err := CheckDockerBridgeMark(inspectRules); err != nil {
			return Backend{}, err
		}
	}
	return backend, nil
}

// Old Docker versions predate the FirewallBackend field and only support the
// iptables driver. Docker 29+ can use native nftables, so a missing field on
// those versions is ambiguous even if old xtables DOCKER hooks remain loaded.
func dockerFirewallDriver(reportedDriver, serverVersion string) (string, error) {
	if reportedDriver != "" {
		return reportedDriver, nil
	}
	majorText, _, _ := strings.Cut(strings.TrimPrefix(serverVersion, "v"), ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 1 {
		return "", fmt.Errorf("Docker did not report FirewallBackend and ServerVersion %q cannot establish a safe fallback", serverVersion)
	}
	if major >= 29 {
		return "", fmt.Errorf("Docker %s did not report FirewallBackend; refusing to infer its active firewall driver from stale host rules", serverVersion)
	}
	return "iptables", nil
}

var dockerBridgeMark = regexp.MustCompile(`meta mark & 0x0*1068 == 0x0*1068`)

// Docker's native bridge firewall evaluates forwarding after our own hook.
// A prior nft accept verdict cannot override Docker's later drop; require the
// matching Docker-owned fwmark exception instead of silently publishing dead
// host ports. We inspect Docker's table but never change it.
func CheckDockerBridgeMark(inspect func(string, ...string) ([]byte, error)) error {
	out, err := inspect("nft", "list", "table", "ip", "docker-bridges")
	if err != nil {
		return fmt.Errorf("inspect Docker native nft bridge rules: %w", err)
	}
	if !dockerBridgeMark.Match(out) {
		return fmt.Errorf("Docker native nftables requires daemon bridge-accept-fwmark=0x1068/0x1068 for platform host ports; configure Docker and restart it before starting the network manager")
	}
	return nil
}

func inspectRules(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Docker's nftables backend does not remove earlier xtables FORWARD policies
// or platform hooks. Inspect both xtables frontends, but invoke the dedicated
// legacy CLI only for tables already loaded in the kernel: even a read-only
// legacy command can otherwise load legacy modules on an nft-only host.
func CheckNativeMigration(lookup lookupFunc, version versionFunc, inspect inspectFunc, readFile readFileFunc) error {
	legacyTables, err := readFile("/proc/net/ip_tables_names")
	if errors.Is(err, os.ErrNotExist) {
		// With no legacy ip_tables module loaded, Linux may omit this proc
		// entry entirely. Absence means there are no loaded legacy tables;
		// unlike an unreadable existing entry, it is safe to continue.
		legacyTables = nil
	} else if err != nil {
		return fmt.Errorf("inspect loaded legacy iptables tables before native nftables: %w", err)
	}
	nftCommand, nftUnavailable, err := nftInspectionCommand(lookup, version)
	if err != nil {
		return fmt.Errorf("find previous iptables-nft rules before native nftables: %w", err)
	}
	if !nftUnavailable {
		for _, table := range []string{"filter", "nat"} {
			if err := checkPreviousXTRules(nftCommand, table, inspect); err != nil {
				return err
			}
		}
	}
	if !hasTable(legacyTables, "filter") && !hasTable(legacyTables, "nat") {
		return nil
	}
	legacyCommand, err := legacyInspectionCommand(lookup, version)
	if err != nil {
		return fmt.Errorf("loaded legacy firewall tables cannot be inspected before native nftables: %w", err)
	}
	for _, table := range []string{"filter", "nat"} {
		if hasTable(legacyTables, table) {
			if err := checkPreviousXTRules(legacyCommand, table, inspect); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkPreviousXTRules(command, table string, inspect inspectFunc) error {
	out, err := inspect(command, "-t", table, "-S")
	if err != nil {
		return fmt.Errorf("inspect previous %s %s rules before native nftables: %w", command, table, err)
	}
	if table == "filter" && hasForwardDropPolicy(out) {
		return fmt.Errorf("Docker native nftables is blocked by a previous %s FORWARD DROP policy; migrate the host firewall explicitly before starting the network manager", command)
	}
	if hook := platformHook(out); hook != "" {
		return fmt.Errorf("previous %s %s hook is still active (%s); remove the platform-owned old hook explicitly before native nftables", command, table, hook)
	}
	if table == "nat" && hasDockerNATChain(out) {
		return fmt.Errorf("previous %s Docker NAT hook is still active; migrate the host firewall explicitly before native nftables", command)
	}
	return nil
}

type lookupFunc func(string) (string, error)
type versionFunc func(string) (string, error)
type inspectFunc func(string, ...string) ([]byte, error)
type readFileFunc func(string) ([]byte, error)

func SelectDockerXTMode(requested, active Mode) (Mode, error) {
	if requested == "" || requested == Auto {
		return active, nil
	}
	if requested != active {
		return "", fmt.Errorf("requested %s frontend differs from Docker's active %s frontend; select %s or correct the host Docker firewall backend", requested, active, active)
	}
	return requested, nil
}

// DetectDockerXTFrontend inspects Docker's *active* NAT chain, not the
// container's generic iptables alternative. Reading /proc/net/ip_tables_names
// first is important: invoking iptables-legacy on an nft-only host can load
// otherwise unused legacy kernel modules, even for an inspection command.
func DetectDockerXTFrontend(lookup lookupFunc, version versionFunc, inspect inspectFunc, readFile readFileFunc) (Mode, error) {
	legacyTables, err := readFile("/proc/net/ip_tables_names")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect loaded legacy iptables tables: %w", err)
	}
	legacyNATLoaded := hasTable(legacyTables, "nat")

	nftCommand, nftUnavailable, err := nftInspectionCommand(lookup, version)
	if err != nil {
		return "", fmt.Errorf("cannot inspect Docker's iptables-nft rules: %w", err)
	}
	nftActive := false
	var nftRules []byte
	if !nftUnavailable {
		var inspectErr error
		nftRules, inspectErr = inspect(nftCommand, "-t", "nat", "-S")
		if inspectErr != nil {
			if !nftBackendUnavailable(nftRules) {
				return "", fmt.Errorf("inspect Docker iptables-nft NAT rules: %w: %s", inspectErr, strings.TrimSpace(string(nftRules)))
			}
			nftUnavailable = true
		} else {
			nftActive = hasDockerNATChain(nftRules)
		}
	}

	legacyActive := false
	var legacyRules []byte
	var legacyCommand string
	if legacyNATLoaded {
		legacyCommand, err = legacyInspectionCommand(lookup, version)
		if err != nil {
			return "", fmt.Errorf("legacy NAT table is loaded but its Docker rules cannot be inspected: %w", err)
		}
		legacyRules, err = inspect(legacyCommand, "-t", "nat", "-S")
		if err != nil {
			return "", fmt.Errorf("inspect Docker iptables-legacy NAT rules: %w", err)
		}
		legacyActive = hasDockerNATChain(legacyRules)
	}
	var active Mode
	switch {
	case nftActive && legacyActive:
		return "", fmt.Errorf("Docker-owned NAT DOCKER chains are active in both iptables-nft and iptables-legacy; remove the stale backend's Docker rules before starting the network manager")
	case nftActive:
		active = IptablesNFT
	case legacyActive:
		active = IptablesLegacy
	default:
		return "", fmt.Errorf("no unique active Docker NAT DOCKER chain was found in iptables-nft or loaded iptables-legacy; start Docker's bridge networking and verify its firewall backend before starting the network manager")
	}
	// A stale platform hook in the other frontend is not evidence that
	// Docker owns it, but it is still live packet processing. Never start a
	// manager which writes only one frontend while the other still owns hooks.
	if active == IptablesNFT {
		if hasTable(legacyTables, "nat") && platformHook(legacyRules) != "" {
			return "", fmt.Errorf("active platform NAT hook remains in iptables-legacy while Docker uses iptables-nft; migrate the old hook explicitly")
		}
		if hasTable(legacyTables, "filter") {
			if legacyCommand == "" {
				legacyCommand, err = legacyInspectionCommand(lookup, version)
				if err != nil {
					return "", fmt.Errorf("loaded legacy filter table cannot be inspected: %w", err)
				}
			}
			filterRules, err := inspect(legacyCommand, "-t", "filter", "-S")
			if err != nil {
				return "", fmt.Errorf("inspect opposite iptables-legacy filter rules: %w", err)
			}
			if platformHook(filterRules) != "" || hasForwardDropPolicy(filterRules) {
				return "", fmt.Errorf("active platform hook or FORWARD DROP remains in iptables-legacy filter while Docker uses iptables-nft; migrate the old rules explicitly")
			}
		}
	} else if !nftUnavailable {
		if platformHook(nftRules) != "" {
			return "", fmt.Errorf("active platform NAT hook remains in iptables-nft while Docker uses iptables-legacy; migrate the old hook explicitly")
		}
		filterRules, err := inspect(nftCommand, "-t", "filter", "-S")
		if err != nil {
			return "", fmt.Errorf("inspect opposite iptables-nft filter rules: %w", err)
		}
		if platformHook(filterRules) != "" || hasForwardDropPolicy(filterRules) {
			return "", fmt.Errorf("active platform hook or FORWARD DROP remains in iptables-nft filter while Docker uses iptables-legacy; migrate the old rules explicitly")
		}
	}
	return active, nil
}

// Inspect a loaded legacy table only through its dedicated frontend. Falling
// back to the generic iptables alternative could read nft rules instead and
// hide a second active Docker backend (or reject an otherwise valid nft host).
func legacyInspectionCommand(lookup lookupFunc, version versionFunc) (string, error) {
	const command = "iptables-legacy"
	if _, err := lookup(command); err != nil {
		return "", fmt.Errorf("find %s: %w", command, err)
	}
	out, err := version(command)
	if err != nil {
		return "", fmt.Errorf("verify %s version: %w", command, err)
	}
	if !strings.Contains(out, "(legacy)") {
		return "", fmt.Errorf("%s is not the legacy frontend: %s", command, strings.TrimSpace(out))
	}
	return command, nil
}

// Only an absent/wrong generic alternative or an explicitly unsupported
// nf_tables kernel is an unavailable frontend. Inspection failures such as
// permission denied remain errors rather than silently selecting legacy.
func nftInspectionCommand(lookup lookupFunc, version versionFunc) (string, bool, error) {
	if _, err := lookup("iptables-nft"); err == nil {
		out, err := version("iptables-nft")
		if err != nil {
			return "", false, fmt.Errorf("iptables-nft version cannot be verified: %w", err)
		}
		if !strings.Contains(out, "nf_tables") {
			return "", false, fmt.Errorf("iptables-nft is not the nf_tables frontend: %s", strings.TrimSpace(out))
		}
		return "iptables-nft", false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("find iptables-nft: %w", err)
	}
	if _, err := lookup("iptables"); errors.Is(err, os.ErrNotExist) {
		return "", true, nil
	} else if err != nil {
		return "", false, fmt.Errorf("find generic iptables: %w", err)
	}
	out, err := version("iptables")
	if err != nil {
		return "", false, fmt.Errorf("generic iptables version cannot be verified: %w", err)
	}
	if strings.Contains(out, "nf_tables") {
		return "iptables", false, nil
	}
	if strings.Contains(out, "legacy") {
		return "", true, nil
	}
	return "", false, fmt.Errorf("unrecognized generic iptables frontend %q", strings.TrimSpace(out))
}

func nftBackendUnavailable(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "protocol not supported") ||
		strings.Contains(message, "operation not supported") ||
		strings.Contains(message, "address family not supported") ||
		strings.Contains(message, "could not fetch rule set generation id: invalid argument")
}

func hasDockerNATChain(rules []byte) bool {
	declared := false
	hooked := false
	for _, line := range strings.Split(string(rules), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "-N" && fields[1] == "DOCKER" {
			declared = true
		}
		if len(fields) >= 4 && fields[0] == "-A" && (fields[1] == "PREROUTING" || fields[1] == "OUTPUT") {
			for i := 2; i+1 < len(fields); i++ {
				if fields[i] == "-j" && fields[i+1] == "DOCKER" {
					hooked = true
				}
			}
		}
	}
	return declared && hooked
}

func platformHook(rules []byte) string {
	type jump struct {
		target string
		line   string
	}
	jumps := make(map[string][]jump)
	for _, line := range strings.Split(string(rules), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "-A" {
			continue
		}
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] == "-j" || fields[i] == "-g" || fields[i] == "--jump" || fields[i] == "--goto" {
				jumps[fields[1]] = append(jumps[fields[1]], jump{fields[i+1], strings.TrimSpace(line)})
				break
			}
		}
	}
	// A declared but disconnected old chain cannot process packets. Traverse
	// from built-in hooks so indirect references remain visible without
	// mistaking orphaned CATTLE_* chains for an active second owner.
	queue := []string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		chain := queue[0]
		queue = queue[1:]
		if seen[chain] {
			continue
		}
		seen[chain] = true
		for _, edge := range jumps[chain] {
			if strings.HasPrefix(edge.target, "CATTLE_") {
				return edge.line
			}
			queue = append(queue, edge.target)
		}
	}
	return ""
}

func hasForwardDropPolicy(rules []byte) bool {
	for _, line := range strings.Split(string(rules), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "-P" && fields[1] == "FORWARD" && fields[2] == "DROP" {
			return true
		}
	}
	return false
}

func hasTable(tables []byte, name string) bool {
	for _, line := range strings.Split(string(tables), "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
}

func commandVersion(name string) (string, error) {
	out, err := exec.Command(name, "--version").CombinedOutput()
	return string(out), err
}

// Resolve is kept independent of Docker and the process PATH for deterministic
// compatibility tests. There is no automatic downgrade on failure.
func Resolve(requested Mode, dockerDriver string, lookup lookupFunc, version versionFunc) (Backend, error) {
	if requested == "" {
		requested = Auto
	}
	if dockerDriver != "iptables" && dockerDriver != "nftables" {
		return Backend{}, fmt.Errorf("unsupported Docker firewall backend %q", dockerDriver)
	}
	if requested == Auto {
		if dockerDriver == "nftables" {
			requested = NFTables
		} else {
			return Backend{}, fmt.Errorf("Docker's active iptables frontend must be inspected before resolving auto mode")
		}
	}
	if requested == NFTables {
		if dockerDriver != "nftables" {
			return Backend{}, fmt.Errorf("native nftables requires Docker firewall-backend=nftables (Docker reports %s)", dockerDriver)
		}
		if _, err := lookup("nft"); err != nil {
			return Backend{}, fmt.Errorf("native nftables requires nft executable: %w", err)
		}
		return Backend{Mode: NFTables, Command: "nft"}, nil
	}
	if dockerDriver == "nftables" {
		return Backend{}, fmt.Errorf("Docker uses native nftables; refusing the incompatible %s frontend", requested)
	}
	var command, restore, marker string
	switch requested {
	case IptablesNFT:
		command, restore, marker = "iptables-nft", "iptables-nft-restore", "nf_tables"
	case IptablesLegacy:
		command, restore, marker = "iptables-legacy", "iptables-legacy-restore", "legacy"
	default:
		return Backend{}, fmt.Errorf("unknown firewall backend %q", requested)
	}
	// Some distributions only install generic alternatives. Never mix a
	// variant's command with another variant's restore binary.
	if _, err := lookup(command); err != nil {
		command = "iptables"
	}
	if _, err := lookup(restore); err != nil {
		restore = "iptables-restore"
	}
	for _, binary := range []string{command, restore} {
		if _, err := lookup(binary); err != nil {
			return Backend{}, fmt.Errorf("%s backend requires %s: %w", requested, binary, err)
		}
		out, err := version(binary)
		if err != nil || !strings.Contains(out, marker) {
			return Backend{}, fmt.Errorf("%s is not the selected %s frontend: %s", binary, requested, strings.TrimSpace(out))
		}
	}
	return Backend{Mode: requested, Command: command, Restore: restore}, nil
}
