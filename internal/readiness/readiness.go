package readiness

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const DefaultPath = "/tmp/pasturestack-network-ready"

type Component string

const (
	HostNAT   Component = "hostnat"
	HostPorts Component = "hostports"
)

// Tracker reflects the latest reconcile result of both firewall watchers.
// Its file is container-local; a previous Docker restart may retain /tmp, so
// New always removes stale readiness before the process starts any work.
type Tracker struct {
	mu    sync.Mutex
	path  string
	nat   bool
	ports bool
}

func New(path string) (*Tracker, error) {
	if path == "" {
		return nil, fmt.Errorf("readiness path is empty")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("clear stale readiness: %w", err)
	}
	return &Tracker{path: path}, nil
}

func (t *Tracker) Report(component Component, reconcileErr error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch component {
	case HostNAT:
		t.nat = reconcileErr == nil
	case HostPorts:
		t.ports = reconcileErr == nil
	default:
		return fmt.Errorf("unknown readiness component %q", component)
	}
	if !t.nat || !t.ports {
		if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear unhealthy readiness: %w", err)
		}
		return nil
	}
	if _, err := os.Stat(t.path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect readiness: %w", err)
	}

	file, err := os.CreateTemp(filepath.Dir(t.path), ".pasturestack-network-ready-")
	if err != nil {
		return fmt.Errorf("create readiness marker: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString("ready\n"); err != nil {
		file.Close()
		return fmt.Errorf("write readiness marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close readiness marker: %w", err)
	}
	if err := os.Rename(file.Name(), t.path); err != nil {
		return fmt.Errorf("publish readiness marker: %w", err)
	}
	return nil
}
