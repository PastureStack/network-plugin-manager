package hostlabel

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
)

const prefix = "__host_label__:"

func IsReference(value string) bool { return strings.HasPrefix(value, prefix) }

// PeerSubnets returns only active peers of a host-specific network. Inactive
// registrations must not break routing, while active hosts without a valid
// unique subnet fail closed instead of widening the firewall exception.
func PeerSubnets(reference, localUUID, localSubnet string, hosts []metadata.Host) ([]string, error) {
	if !IsReference(reference) {
		return nil, nil
	}
	local, err := netip.ParsePrefix(localSubnet)
	if err != nil || !local.Addr().Is4() {
		return nil, fmt.Errorf("invalid local per-host subnet %q", localSubnet)
	}
	peers := make([]string, 0)
	seen := []netip.Prefix{local}
	for _, host := range hosts {
		if host.UUID == localUUID || host.State != "active" {
			continue
		}
		value, err := Resolve(reference, host.Labels)
		if err != nil {
			return nil, fmt.Errorf("active peer %s: %w", host.UUID, err)
		}
		peer, err := netip.ParsePrefix(value)
		if err != nil || !peer.Addr().Is4() {
			return nil, fmt.Errorf("active peer %s has invalid subnet %q", host.UUID, value)
		}
		for _, existing := range seen {
			if existing.Contains(peer.Addr()) || peer.Contains(existing.Addr()) {
				return nil, fmt.Errorf("active peer %s subnet %s overlaps %s", host.UUID, peer, existing)
			}
		}
		seen = append(seen, peer)
		peers = append(peers, value)
	}
	sort.Strings(peers)
	return peers, nil
}

// Resolve expands only the explicit host-label reference used by network
// drivers. Literal, already-resolved values keep their existing behavior.
func Resolve(value string, labels map[string]string) (string, error) {
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	key := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	if key == "" || strings.ContainsAny(key, " \t\r\n") {
		return "", fmt.Errorf("invalid network host-label reference")
	}
	resolved := strings.TrimSpace(labels[key])
	if resolved == "" {
		return "", fmt.Errorf("network host label %q is missing or empty", key)
	}
	ip, subnet, err := net.ParseCIDR(resolved)
	if err != nil || ip.To4() == nil || !ip.Equal(subnet.IP) {
		return "", fmt.Errorf("network host label %q must be a canonical IPv4 subnet", key)
	}
	return resolved, nil
}
