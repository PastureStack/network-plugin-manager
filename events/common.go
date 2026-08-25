package events

import (
	"context"

	"github.com/moby/moby/client"
)

type SimpleDockerClient interface {
	ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error)
}
