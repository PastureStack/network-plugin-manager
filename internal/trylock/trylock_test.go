package trylock

import "testing"

func TestLockRejectsDuplicateAndReleases(t *testing.T) {
	unlock := Lock("start.container")
	if unlock == nil {
		t.Fatal("first lock failed")
	}
	if duplicate := Lock("start.container"); duplicate != nil {
		duplicate()
		t.Fatal("duplicate lock succeeded")
	}
	unlock()
	second := Lock("start.container")
	if second == nil {
		t.Fatal("released key remained locked")
	}
	second()
}
