package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/PastureStack/network-plugin-manager/internal/logsafe"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

const (
	containerMountPrefix = "/var/lib/docker/containers/"
	containerUUIDLabel   = "io.rancher.container.uuid"
	containerNameLabel   = "io.rancher.container.name"
)

// LocalHost returns the host that this plugin-manager container is running on.
// The metadata /self/host response is source-IP based and can be wrong for host
// network containers on newer distros, because host-originated metadata calls
// share docker0 gateway addresses across hosts.
func LocalHost(mc metadata.Client, dc *client.Client) (metadata.Host, error) {
	hostUUID, err := LocalHostUUID(mc, dc)
	if err != nil {
		return metadata.Host{}, err
	}

	hosts, err := mc.GetHosts()
	if err != nil {
		return metadata.Host{}, fmt.Errorf("get hosts: %w", err)
	}

	for _, host := range hosts {
		if host.UUID == hostUUID {
			return host, nil
		}
	}

	selfHost, err := mc.GetSelfHost()
	if err != nil {
		return metadata.Host{}, err
	}
	if selfHost.UUID == hostUUID {
		return selfHost, nil
	}

	return metadata.Host{}, fmt.Errorf("local host UUID %s not found in metadata hosts", hostUUID)
}

// LocalHostUUID resolves this container's platform HostUUID without relying on
// metadata /self endpoints.
func LocalHostUUID(mc metadata.Client, dc *client.Client) (string, error) {
	if hostUUID, err := localHostUUIDFromDockerLabels(mc, dc); err == nil && hostUUID != "" {
		return hostUUID, nil
	} else if err != nil {
		logrus.Warnf("identity: docker-label host lookup failed, falling back to metadata self host: %s", logsafe.Value(err))
	}

	host, err := mc.GetSelfHost()
	if err != nil {
		return "", fmt.Errorf("get self host: %w", err)
	}
	if host.UUID == "" {
		return "", errors.New("metadata self host has empty uuid")
	}
	return host.UUID, nil
}

func localHostUUIDFromDockerLabels(mc metadata.Client, dc *client.Client) (string, error) {
	id, err := currentContainerID()
	if err != nil {
		return "", err
	}

	inspectResult, err := dc.ContainerInspect(context.Background(), id, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect current container %s: %w", id, err)
	}
	inspect := inspectResult.Container
	if inspect.Config == nil {
		return "", errors.New("current container inspect has no config")
	}

	labels := inspect.Config.Labels
	ownUUID := labels[containerUUIDLabel]
	ownName := labels[containerNameLabel]
	ownExternalID := inspect.ID

	if ownUUID == "" && ownName == "" && ownExternalID == "" {
		return "", errors.New("current container has no compatible identity labels")
	}

	services, err := mc.GetServices()
	if err != nil {
		return "", fmt.Errorf("get services: %w", err)
	}

	for _, service := range services {
		for _, container := range service.Containers {
			if ownUUID != "" && container.UUID == ownUUID {
				return container.HostUUID, nil
			}
			if ownExternalID != "" && container.ExternalId == ownExternalID {
				return container.HostUUID, nil
			}
			if ownName != "" && container.Name == ownName {
				return container.HostUUID, nil
			}
		}
	}

	return "", fmt.Errorf("current container not found in metadata services uuid=%s name=%s id=%s", ownUUID, ownName, ownExternalID)
}

func currentContainerID() (string, error) {
	content, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}

	for _, line := range strings.Split(string(content), "\n") {
		if !strings.Contains(line, "/etc/hosts") &&
			!strings.Contains(line, "/etc/hostname") &&
			!strings.Contains(line, "/etc/resolv.conf") {
			continue
		}

		idx := strings.Index(line, containerMountPrefix)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(containerMountPrefix):]
		slash := strings.Index(rest, "/")
		if slash <= 0 {
			continue
		}
		return rest[:slash], nil
	}

	return "", errors.New("current container id not found in mountinfo")
}
