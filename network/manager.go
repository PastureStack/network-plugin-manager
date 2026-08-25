package network

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/cniglue"
	"github.com/PastureStack/network-plugin-manager/internal/keylock"
	"github.com/containerd/errdefs"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

const (
	maxRetries            = 15
	IPLabel               = "io.rancher.container.ip"
	LegacyManagedNetLabel = "io.rancher.container.network"
	CNILabel              = "io.rancher.cni.network"
	rootStateDir          = "/var/lib/pasturestack/state/cni"
)

type Manager struct {
	c     *client.Client
	s     *state
	locks keylock.Map
}

func NewManager(c *client.Client) (*Manager, error) {
	s, err := newState(rootStateDir, c)
	if err != nil {
		return nil, err
	}
	return &Manager{
		c: c,
		s: s,
	}, nil
}

// Evaluate checks the state and enables networking if needed
func (n *Manager) Evaluate(id string) error {
	return n.evaluate(id, 0)
}

func (n *Manager) evaluate(id string, retryCount int) error {
	unlock := n.locks.Lock(id)
	defer unlock()

	wasTime := n.s.StartTime(id)
	wasRunning := wasTime != ""
	running := false
	time := ""

	inspectResult, err := n.c.ContainerInspect(context.Background(), id, client.ContainerInspectOptions{})
	if errdefs.IsNotFound(err) {
		running = false
		time = ""
	} else if err != nil {
		return err
	} else {
		inspect := inspectResult.Container
		if !configureNetwork(&inspect) {
			return nil
		}
		running = inspect.State.Running
		time = inspect.State.StartedAt
	}

	logrus.WithFields(logrus.Fields{
		"wasTime":    wasTime,
		"wasRunning": wasRunning,
		"running":    running,
		"time":       time,
		"cid":        id,
	}).Debugf("Evaluating networking start")

	if wasRunning {
		if running && wasTime != time {
			return n.networkUp(id, inspectResult.Container, retryCount)
		} else if !running {
			return n.networkDown(id, inspectResult.Container)
		}
	} else if running {
		return n.networkUp(id, inspectResult.Container, retryCount)
	}

	return nil
}

func (n *Manager) retry(id string, retryCount int) {
	time.Sleep(2 * time.Second)
	logrus.WithFields(logrus.Fields{"cid": id, "count": retryCount}).Infof("Evaluating state from retry")
	if err := n.evaluate(id, retryCount); err != nil {
		logrus.Errorf("Failed to evaluate networking: %v", err)
	}
}

func (n *Manager) networkUp(id string, inspect container.InspectResponse, retryCount int) (err error) {
	logrus.WithFields(logrus.Fields{"networkMode": inspect.HostConfig.NetworkMode, "cid": inspect.ID}).Infof("CNI up")
	startedAt := inspect.State.StartedAt

	pluginState, err := cniglue.LookupPluginState(inspect)
	if err != nil {
		return n.s.recordNetworkUpError(id, startedAt, fmt.Errorf("find CNI plugin state: %w", err))
	}
	result, err := cniglue.CNIAdd(pluginState)
	if err != nil {
		if retryCount < maxRetries {
			go n.retry(id, retryCount+1)
			return err
		}
		return n.s.recordNetworkUpError(id, startedAt, fmt.Errorf("bring up CNI network: %w", err))
	}
	logrus.WithFields(logrus.Fields{
		"networkMode": inspect.HostConfig.NetworkMode,
		"cid":         inspect.ID,
		"result":      result,
	}).Infof("CNI up done")
	if err := n.setupHosts(inspect, result); err != nil {
		return n.s.recordNetworkUpError(id, startedAt, fmt.Errorf("set up container hosts file: %w", err))
	}
	n.s.Started(id, inspect.State.StartedAt, result)
	return nil
}

func (n *Manager) setupHosts(inspect container.InspectResponse, result *types100.Result) error {
	ip := cniglue.PrimaryIPv4(result)
	if inspect.Config == nil || inspect.Config.Hostname == "" || inspect.HostsPath == "" ||
		ip == "" {
		return nil
	}

	hosts, err := os.ReadFile(inspect.HostsPath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	hostsString := string(hosts)
	line := fmt.Sprintf("\n%s\t%s\n", ip, inspect.Config.Hostname)
	if strings.Contains(hostsString, line) {
		return nil
	}

	updatedHosts := hostsString + line
	return os.WriteFile(inspect.HostsPath, []byte(updatedHosts), 0644)
}

func (n *Manager) networkDown(id string, inspect container.InspectResponse) error {
	defer n.s.Stopped(id)
	if inspect.HostConfig == nil {
		return nil
	}
	logrus.WithFields(logrus.Fields{"networkMode": inspect.HostConfig.NetworkMode, "cid": inspect.ID}).Infof("CNI down")
	pluginState, err := cniglue.LookupPluginState(inspect)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("find CNI plugin state on down: %w", err)
	}
	return cniglue.CNIDel(pluginState)
}

func configureNetwork(inspect *container.InspectResponse) bool {
	if inspect == nil || inspect.Config == nil || inspect.HostConfig == nil {
		return false
	}
	net, ok := inspect.Config.Labels[CNILabel]
	if !ok && (inspect.Config.Labels[LegacyManagedNetLabel] == "true" || inspect.Config.Labels[IPLabel] != "") {
		net = "managed"
	}

	if net == "" {
		return false
	}

	inspect.HostConfig.NetworkMode = container.NetworkMode(net)
	return true
}
