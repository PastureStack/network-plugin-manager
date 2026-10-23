package events

import (
	"testing"

	"github.com/PastureStack/network-plugin-manager/binexec"
	mobyevents "github.com/moby/moby/api/types/events"
)

func TestDriverSelectionIsNotifiedBeforeNetworkingOnStartAndDie(t *testing.T) {
	watcher := &binexec.Watcher{}
	processor := &DockerEventsProcessor{bw: watcher}
	handlers := processor.eventHandlers()
	for _, action := range []mobyevents.Action{mobyevents.ActionStart, mobyevents.ActionDie} {
		if len(handlers[action]) < 2 || handlers[action][0] != watcher {
			t.Fatalf("%s must notify binexec before network reconciliation", action)
		}
		if _, ok := handlers[action][len(handlers[action])-1].(*NetworkManagerHandler); !ok {
			t.Fatalf("%s lost its existing network handler", action)
		}
	}
}
