package events

import (
	"context"
	"errors"
	"io"
	"time"

	mobyevents "github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	log "github.com/sirupsen/logrus"
)

const workerTimeout = 60 * time.Second

type Handler interface {
	Handle(*mobyevents.Message) error
}

type EventRouter struct {
	handlers      map[mobyevents.Action][]Handler
	dockerClient  *client.Client
	workers       chan *worker
	workerTimeout time.Duration
	cancel        context.CancelFunc
}

func NewEventRouter(_ int, workerPoolSize int, dockerClient *client.Client,
	handlers map[mobyevents.Action][]Handler,
) (*EventRouter, error) {
	workers := make(chan *worker, workerPoolSize)
	for i := 0; i < workerPoolSize; i++ {
		workers <- &worker{}
	}
	return &EventRouter{
		handlers:      handlers,
		dockerClient:  dockerClient,
		workers:       workers,
		workerTimeout: workerTimeout,
	}, nil
}

func (e *EventRouter) Start() error {
	log.Info("Starting event router.")
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	result := e.dockerClient.Events(ctx, client.EventsListOptions{})
	go e.routeEvents(ctx, result)
	return nil
}

func (e *EventRouter) Stop() error {
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	return nil
}

func (e *EventRouter) routeEvents(ctx context.Context, result client.EventsResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-result.Err:
			if ok && err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				log.Errorf("Docker event stream stopped: %v", err)
			}
			return
		case event, ok := <-result.Messages:
			if !ok {
				return
			}
			e.processEvent(ctx, &event)
		}
	}
}

func (e *EventRouter) processEvent(ctx context.Context, event *mobyevents.Message) {
	timer := time.NewTimer(e.workerTimeout)
	defer timer.Stop()
	for {
		select {
		case w := <-e.workers:
			go w.doWork(event, e)
			return
		case <-timer.C:
			log.Info("Timed out waiting for Docker event worker; continuing to wait")
			timer.Reset(e.workerTimeout)
		case <-ctx.Done():
			return
		}
	}
}

type worker struct{}

func (w *worker) doWork(event *mobyevents.Message, router *EventRouter) {
	defer func() { router.workers <- w }()
	if event == nil {
		return
	}
	if handlers, ok := router.handlers[event.Action]; ok {
		log.Debugf("Processing event: %#v", event)
		for _, handler := range handlers {
			if err := handler.Handle(event); err != nil {
				log.Errorf("Error processing event %#v: %v", event, err)
			}
		}
	}
}
