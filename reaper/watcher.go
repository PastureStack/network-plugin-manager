package reaper

import (
	"context"
	"fmt"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/containerd/errdefs"
	"github.com/jpillora/backoff"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	uuidLabel        = "io.rancher.container.uuid"
	serviceNameLabel = "io.rancher.stack_service.name"
	metadataService  = "network-services/metadata"
	dnsService       = "network-services/metadata/dns"

	recheckEvery = 5 * time.Minute
)

func Watch(dockerClient *client.Client, c metadata.Client) error {
	w := &watcher{
		dc: dockerClient,
		c:  c,
	}
	go c.OnChange(5, w.onChangeNoError)
	go watchMetadata(dockerClient)
	return nil
}

func watchMetadata(dockerClient *client.Client) {
	b := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    5 * time.Minute,
		Factor: 1.5,
	}
	for {
		err := CheckMetadata(dockerClient, false)
		if err != nil {
			logrus.Errorf("Failed to check for bad metadata: %v", err)
		}
		time.Sleep(b.Duration())
	}
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

	for _, container := range containers {
		if container.HostUUID != host.UUID {
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

	return nil
}

func CheckMetadata(dockerClient *client.Client, first bool) error {
	result, err := dockerClient.ContainerList(context.Background(), client.ContainerListOptions{
		All: true,
	})
	if err != nil {
		return err
	}

	metadataIds := []string{}
	dnsIds := []string{}
	for _, summary := range result.Items {
		if summary.Labels[uuidLabel] != "" && summary.Labels[serviceNameLabel] == metadataService {
			metadataIds = append(metadataIds, summary.ID)
		}
		if summary.Labels[uuidLabel] != "" && summary.Labels[serviceNameLabel] == dnsService {
			dnsIds = append(dnsIds, summary.ID)
		}
	}

	toDelete := []string{}

	if len(metadataIds) > 1 {
		toDelete = append(toDelete, metadataIds...)
		toDelete = append(toDelete, dnsIds...)
	} else if len(dnsIds) > 1 {
		toDelete = append(toDelete, dnsIds...)
	} else if first && len(dnsIds) == 1 {
		dnsResult, err := dockerClient.ContainerInspect(context.Background(), dnsIds[0], client.ContainerInspectOptions{})
		if err != nil {
			return err
		}
		if dnsResult.Container.HostConfig == nil {
			return fmt.Errorf("DNS container %s has no host configuration", dnsIds[0])
		}
		id := dnsResult.Container.HostConfig.NetworkMode.ConnectedContainer()
		_, err = dockerClient.ContainerInspect(context.Background(), id, client.ContainerInspectOptions{})
		if errdefs.IsNotFound(err) {
			logrus.Errorf("Failed to find network container [%s] for DNS %s", id, dnsIds[0])
			toDelete = append(toDelete, dnsIds...)
		}
	}

	for _, id := range toDelete {
		logrus.Infof("Deleting duplicate metadata/dns service: %s", id)
		_, err := dockerClient.ContainerRemove(context.Background(), id, client.ContainerRemoveOptions{
			Force: true,
		})
		if err != nil {
			logrus.Errorf("Failed to remove duplicate metadata/dns service: %s", id)
		}
	}

	return nil
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
