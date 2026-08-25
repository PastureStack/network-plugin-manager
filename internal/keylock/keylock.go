// Package keylock serializes work that targets the same runtime object while
// allowing unrelated objects to progress independently.
package keylock

import "sync"

type entry struct {
	mu   sync.Mutex
	refs int
}

// Map is a bounded-lifetime keyed lock set. Entries are removed after the last
// waiter releases them, so long-running hosts do not retain container IDs.
type Map struct {
	mu      sync.Mutex
	entries map[string]*entry
}

// Lock acquires key and returns its idempotent unlock function.
func (m *Map) Lock(key string) func() {
	m.mu.Lock()
	if m.entries == nil {
		m.entries = make(map[string]*entry)
	}
	e := m.entries[key]
	if e == nil {
		e = &entry{}
		m.entries[key] = e
	}
	e.refs++
	m.mu.Unlock()

	e.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Unlock()
			m.mu.Lock()
			e.refs--
			if e.refs == 0 {
				delete(m.entries, key)
			}
			m.mu.Unlock()
		})
	}
}
