package keylock

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestMapSerializesSameKeyAndReleasesEntry(t *testing.T) {
	var locks Map
	unlock := locks.Lock("container")
	entered := make(chan struct{})
	var ran atomic.Bool
	go func() {
		defer close(entered)
		defer locks.Lock("container")()
		ran.Store(true)
	}()

	select {
	case <-entered:
		t.Fatal("same key was not serialized")
	case <-time.After(20 * time.Millisecond):
	}
	unlock()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("waiter was not released")
	}
	if !ran.Load() {
		t.Fatal("waiter did not run")
	}
	if len(locks.entries) != 0 {
		t.Fatalf("entries retained after final unlock: %d", len(locks.entries))
	}
}
