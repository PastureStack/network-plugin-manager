package events

import (
	"context"

	"github.com/PastureStack/network-plugin-manager/binexec"
	"github.com/PastureStack/network-plugin-manager/network"
	mobyevents "github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

const simulatedEvent = "initial-container-snapshot"

func Watch(poolSize int, dockerClient *client.Client, manager *network.Manager, binaryWatcher *binexec.Watcher) error {
	processor := &DockerEventsProcessor{
		poolSize:     poolSize,
		dockerClient: dockerClient,
		nm:           manager,
		bw:           binaryWatcher,
	}
	return processor.Process()
}

type DockerEventsProcessor struct {
	poolSize     int
	dockerClient *client.Client
	nm           *network.Manager
	bw           *binexec.Watcher
}

func (processor *DockerEventsProcessor) Process() error {
	networkHandler := &NetworkManagerHandler{nm: processor.nm}
	handlers := map[mobyevents.Action][]Handler{
		mobyevents.ActionStart: {
			processor.bw,
			&StartHandler{Client: processor.dockerClient},
			networkHandler,
		},
		mobyevents.ActionDie: {networkHandler},
	}

	router, err := NewEventRouter(processor.poolSize, processor.poolSize, processor.dockerClient, handlers)
	if err != nil {
		return err
	}
	if err := router.Start(); err != nil {
		return err
	}

	result, err := processor.dockerClient.ContainerList(context.Background(), client.ContainerListOptions{All: true})
	if err != nil {
		_ = router.Stop()
		return err
	}
	for _, summary := range result.Items {
		event := &mobyevents.Message{
			Action: mobyevents.ActionStart,
			Actor: mobyevents.Actor{
				ID:         summary.ID,
				Attributes: map[string]string{"source": simulatedEvent},
			},
		}
		router.processEvent(context.Background(), event)
	}
	return nil
}
