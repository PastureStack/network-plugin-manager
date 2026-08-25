package cniglue

import "github.com/moby/moby/api/types/container"

// DockerPluginState is the subset of Docker inspect data required to invoke CNI.
type DockerPluginState struct {
	ContainerID string
	HostConfig  container.HostConfig
	Config      container.Config
	PID         int
}

func LookupPluginState(inspect container.InspectResponse) (*DockerPluginState, error) {
	result := &DockerPluginState{ContainerID: inspect.ID}
	if inspect.HostConfig != nil {
		result.HostConfig = *inspect.HostConfig
	}
	if inspect.Config != nil {
		result.Config = *inspect.Config
	}
	if inspect.State != nil {
		result.PID = inspect.State.Pid
	}
	return result, nil
}
