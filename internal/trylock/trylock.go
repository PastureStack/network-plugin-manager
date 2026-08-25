// Package trylock provides the event de-duplication lock used by container
// start handlers. A duplicate event is skipped instead of queued.
package trylock

import "sync"

var held = struct {
	sync.Mutex
	keys map[string]struct{}
}{keys: make(map[string]struct{})}

// Lock returns an unlock function, or nil when key is already being handled.
func Lock(key string) func() {
	held.Lock()
	defer held.Unlock()
	if _, exists := held.keys[key]; exists {
		return nil
	}
	held.keys[key] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			held.Lock()
			delete(held.keys, key)
			held.Unlock()
		})
	}
}
