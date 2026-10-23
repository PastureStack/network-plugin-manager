package reaper

import (
	"context"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	uuidLabel        = "io.rancher.container.uuid"
	serviceNameLabel = "io.rancher.stack_service.name"
	metadataService  = "network-services/metadata"
	dnsService       = "network-services/metadata/dns"
)

func Watch(dockerClient *client.Client, c metadata.Client) error {
	w := &watcher{
		dc: dockerClient,
		c:  c,
	}
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

type watcher struct {
	dc *client.Client
	c  metadata.Client
}

func (w *watcher) onChangeNoError(version string) {
	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to watch for orphan containers: %v", err)
	}
}

func (w *watcher) onChange(version string) error {
	host, err := identity.LocalHost(w.c, w.dc)
	if err != nil {
		return err
	}

	containers, err := w.c.GetContainers()
	if err != nil {
		return err
	}

	w.removeUnmanaged(containers, host.UUID)
	return nil
}

func (w *watcher) removeUnmanaged(containers []metadata.Container, hostUUID string) {
	for _, container := range containers {
		if container.HostUUID != hostUUID || managedDependency(container) {
			continue
		}
		uuid, ok := container.Labels[uuidLabel]
		if !ok {
			continue
		}

		if container.UUID != uuid {
			w.removeContainer(container)
		}
	}
}

// Metadata and DNS are dependencies owned by the orchestration lifecycle, not
// this plugin. Old/new instances and temporarily missing network namespaces are
// valid during replacement; only the owner can decide when to remove them.
func managedDependency(container metadata.Container) bool {
	name := container.Labels[serviceNameLabel]
	if name == metadataService || name == dnsService {
		return true
	}
	return container.StackName == "network-services" &&
		(container.ServiceName == "metadata" || container.ServiceName == "metadata/dns" || container.ServiceName == "dns")
}

func (w *watcher) removeContainer(container metadata.Container) {
	logrus.Infof("Removing unmanaged container %s %s", container.Name, container.ExternalId)
	_, err := w.dc.ContainerRemove(context.Background(), container.ExternalId, client.ContainerRemoveOptions{
		Force: true,
	})
	if err != nil {
		logrus.Errorf("Removed failed: %v", err)
	}
}
