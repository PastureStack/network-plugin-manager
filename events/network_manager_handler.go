package events

import (
	"github.com/PastureStack/network-plugin-manager/network"
	mobyevents "github.com/moby/moby/api/types/events"
	"github.com/sirupsen/logrus"
)

type NetworkManagerHandler struct {
	nm *network.Manager
}

func (handler *NetworkManagerHandler) Handle(event *mobyevents.Message) error {
	if err := handler.nm.Evaluate(event.Actor.ID); err != nil {
		logrus.Errorf("Failed to evaluate network state for %s: %v", event.Actor.ID, err)
		return err
	}
	return nil
}
