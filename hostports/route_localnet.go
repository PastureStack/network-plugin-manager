package hostports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const routeLocalnetStatePath = "/run/pasturestack/network-plugin-manager/route-localnet.json"

type persistedRouteLocalnetState struct {
	Version  int             `json:"version"`
	Original map[string]bool `json:"original"`
}

func loadRouteLocalnetState(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var state persistedRouteLocalnetState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if state.Version != 1 || state.Original == nil {
		return nil, fmt.Errorf("unsupported or incomplete state in %s", path)
	}
	for bridge := range state.Original {
		if err := validateBridgeName(bridge); err != nil {
			return nil, fmt.Errorf("invalid persisted bridge: %w", err)
		}
	}
	return state.Original, nil
}

func saveRouteLocalnetState(path string, original map[string]bool) error {
	if path == "" {
		return nil
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(persistedRouteLocalnetState{Version: 1, Original: original})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(directory, ".route-localnet-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func readBridgeRouteLocalnet(bridge string) (bool, error) {
	if err := validateBridgeName(bridge); err != nil {
		return false, err
	}
	path := "/proc/sys/net/ipv4/conf/" + bridge + "/route_localnet"
	value, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(value)) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("unexpected route_localnet value for bridge %s", bridge)
	}
}

func setBridgeRouteLocalnet(bridge string, enabled bool) error {
	if err := validateBridgeName(bridge); err != nil {
		return err
	}
	path := "/proc/sys/net/ipv4/conf/" + bridge + "/route_localnet"
	value := []byte("0\n")
	if enabled {
		value = []byte("1\n")
	}
	if err := os.WriteFile(path, value, 0644); err != nil {
		if !enabled && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

func sortedEnabledBridges(bridges map[string]bool) []string {
	names := []string{}
	for bridge, enabled := range bridges {
		if enabled {
			names = append(names, bridge)
		}
	}
	sort.Strings(names)
	return names
}

// restoreRemovedRouteLocalnet runs after a complete firewall precheck and
// before a guard is removed. It restores only values previously changed by
// this process family, as recorded on the host-mounted /run filesystem.
func (w *watcher) restoreRemovedRouteLocalnet(rules ruleSet) error {
	if w.setRouteLocalnet == nil {
		return nil
	}
	bridges := make([]string, 0, len(w.routeLocalnetOriginal))
	for bridge := range w.routeLocalnetOriginal {
		if !rules.RouteLocalnetBridges[bridge] {
			bridges = append(bridges, bridge)
		}
	}
	sort.Strings(bridges)
	for _, bridge := range bridges {
		if err := w.setRouteLocalnet(bridge, w.routeLocalnetOriginal[bridge]); err != nil {
			return fmt.Errorf("restore route_localnet on bridge %s: %w", bridge, err)
		}
	}
	return nil
}

// activateRouteLocalnet is called only after the bridge-scoped 127/8 guard is
// live. Ownership is persisted before enabling so a process restart can still
// restore the original per-bridge value.
func (w *watcher) activateRouteLocalnet(rules ruleSet) error {
	if w.setRouteLocalnet == nil {
		return nil
	}
	if w.getRouteLocalnet == nil {
		return fmt.Errorf("route_localnet reader is not configured")
	}
	next := map[string]bool{}
	for _, bridge := range sortedEnabledBridges(rules.RouteLocalnetBridges) {
		original, known := w.routeLocalnetOriginal[bridge]
		if !known {
			var err error
			original, err = w.getRouteLocalnet(bridge)
			if err != nil {
				return fmt.Errorf("read route_localnet on bridge %s: %w", bridge, err)
			}
		}
		next[bridge] = original
	}
	if err := saveRouteLocalnetState(w.routeLocalnetStatePath, next); err != nil {
		return fmt.Errorf("persist route_localnet ownership: %w", err)
	}
	w.routeLocalnetOriginal = next
	for _, bridge := range sortedEnabledBridges(rules.RouteLocalnetBridges) {
		if err := w.setRouteLocalnet(bridge, true); err != nil {
			return fmt.Errorf("enable guarded route_localnet on bridge %s: %w", bridge, err)
		}
	}
	return nil
}
