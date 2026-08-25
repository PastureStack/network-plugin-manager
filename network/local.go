package network

import (
	"context"
	"fmt"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/moby/moby/client"
)

func LocalNetworks(mc metadata.Client, dc *client.Client) ([]metadata.Network, map[string]metadata.Container, error) {
	networks, err := mc.GetNetworks()
	if err != nil {
		return nil, nil, fmt.Errorf("fetch networks from metadata: %w", err)
	}

	hostUUID, err := identity.LocalHostUUID(mc, dc)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch local host UUID: %w", err)
	}

	services, err := mc.GetServices()
	if err != nil {
		return nil, nil, fmt.Errorf("fetch services from metadata: %w", err)
	}

	localNetworks := map[string]bool{}
	routers := map[string]metadata.Container{}
	for _, service := range services {
		// Trick to select the primary service of the network plugin
		// stack
		// TODO: Need to check if it's needed for Calico?
		if !(service.Kind == "networkDriverService" &&
			service.Name == service.PrimaryServiceName) {
			continue
		}

		for _, aContainer := range service.Containers {
			if aContainer.HostUUID == hostUUID {
				routers[aContainer.NetworkUUID] = aContainer
				localNetworks[aContainer.NetworkUUID] = true
			}
		}
	}

	if len(localNetworks) == 0 {
		return nil, nil, nil
	}

	ret := []metadata.Network{}
	for _, aNetwork := range networks {
		if _, ok := localNetworks[aNetwork.UUID]; ok {
			ret = append(ret, aNetwork)
		}
	}

	return ret, routers, nil
}

func ForEachContainerNS(dc *client.Client, mc metadata.Client, networkUUID string, f func(metadata.Container, ns.NetNS) error) error {
	hostUUID, err := identity.LocalHostUUID(mc, dc)
	if err != nil {
		return fmt.Errorf("fetch local host UUID: %w", err)
	}

	containers, err := mc.GetContainers()
	if err != nil {
		return fmt.Errorf("fetch containers from metadata: %w", err)
	}

	var lastError error
	for _, aContainer := range containers {
		if !(aContainer.HostUUID == hostUUID &&
			aContainer.State == "running" &&
			aContainer.ExternalId != "" &&
			aContainer.PrimaryIp != "" &&
			aContainer.PrimaryMacAddress != "" &&
			aContainer.NetworkUUID == networkUUID) {
			continue
		}

		err := EnterNS(dc, aContainer.ExternalId, func(n ns.NetNS) error {
			return f(aContainer, n)
		})
		if err != nil {
			lastError = err
		}
	}

	return lastError
}

func EnterNS(dc *client.Client, dockerID string, f func(ns.NetNS) error) error {
	inspectResult, err := dc.ContainerInspect(context.Background(), dockerID, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect container %s: %w", dockerID, err)
	}
	inspect := inspectResult.Container

	containerNSStr := fmt.Sprintf("/proc/%v/ns/net", inspect.State.Pid)
	netns, err := ns.GetNS(containerNSStr)
	if err != nil {
		return fmt.Errorf("open network namespace %s: %w", containerNSStr, err)
	}
	defer netns.Close()

	err = netns.Do(func(n ns.NetNS) error {
		return f(n)
	})
	if err != nil {
		return fmt.Errorf("run in network namespace for container %s: %w", dockerID, err)
	}

	return nil
}
