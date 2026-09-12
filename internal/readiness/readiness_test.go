package readiness

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTrackerRequiresBothAndRevokesOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	tracker, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	assertMarker := func(want bool) {
		t.Helper()
		_, err := os.Stat(path)
		if (err == nil) != want {
			t.Fatalf("readiness marker present=%t, want=%t: %v", err == nil, want, err)
		}
	}
	assertMarker(false)
	if err := tracker.Report(HostNAT, nil); err != nil {
		t.Fatal(err)
	}
	assertMarker(false)
	if err := tracker.Report(HostPorts, nil); err != nil {
		t.Fatal(err)
	}
	assertMarker(true)
	if err := tracker.Report(HostNAT, errors.New("metadata unavailable")); err != nil {
		t.Fatal(err)
	}
	assertMarker(false)
	if err := tracker.Report(HostNAT, nil); err != nil {
		t.Fatal(err)
	}
	assertMarker(true)
	if err := tracker.Report(HostPorts, errors.New("invalid port")); err != nil {
		t.Fatal(err)
	}
	assertMarker(false)
}

func TestTrackerRejectsUnknownComponent(t *testing.T) {
	tracker, err := New(filepath.Join(t.TempDir(), "ready"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Report(Component("other"), nil); err == nil {
		t.Fatal("unknown component was accepted")
	}
}
