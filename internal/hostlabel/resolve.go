package hostlabel

import (
	"fmt"
	"strings"
)

const prefix = "__host_label__:"

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
	return resolved, nil
}

