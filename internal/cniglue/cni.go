package cniglue

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/containernetworking/cni/libcni"
	types100 "github.com/containernetworking/cni/pkg/types/100"
)

var (
	CniDir  = "/etc/docker/cni/%s.d"
	CniPath = []string{
		"/opt/cni/bin",
		"/var/lib/cni/bin",
		"/usr/local/sbin",
		"/usr/sbin",
		"/sbin",
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
	}
)

type CNIExec struct {
	confs       []*libcni.PluginConfig
	runtimeConf libcni.RuntimeConf
	cninet      *libcni.CNIConfig
}

func (c *CNIExec) Add(index int) (*types100.Result, error) {
	result, err := c.cninet.AddNetwork(context.Background(), c.confs[index], &c.runtimeConf)
	if err != nil {
		return nil, err
	}
	return types100.NewResultFromResult(result)
}

func (c *CNIExec) Del(index int) error {
	runtimeConf := c.runtimeConf
	runtimeConf.NetNS = ""
	return c.cninet.DelNetwork(context.Background(), c.confs[index], &runtimeConf)
}

func NewCNIExec(state *DockerPluginState) (*CNIExec, error) {
	if state == nil {
		return nil, fmt.Errorf("CNI state is nil")
	}
	if state.HostConfig.NetworkMode.IsContainer() || state.HostConfig.NetworkMode.IsHost() || state.HostConfig.NetworkMode.IsNone() {
		return &CNIExec{cninet: libcni.NewCNIConfig(CniPath, nil)}, nil
	}

	c := &CNIExec{
		runtimeConf: libcni.RuntimeConf{
			ContainerID: state.ContainerID,
			NetNS:       fmt.Sprintf("/proc/%d/ns/net", state.PID),
			IfName:      "eth0",
			Args: [][2]string{
				{"IgnoreUnknown", "1"},
				{"DOCKER", "true"},
			},
		},
		cninet: libcni.NewCNIConfig(CniPath, nil),
	}

	if uuid := state.Config.Labels["io.rancher.container.uuid"]; uuid != "" {
		c.runtimeConf.Args = append(c.runtimeConf.Args,
			[2]string{"RancherContainerUUID", uuid},
			[2]string{"PlatformContainerUUID", uuid},
		)
	}
	if overhead := state.Config.Labels["io.rancher.cni.link_mtu_overhead"]; overhead != "" {
		c.runtimeConf.Args = append(c.runtimeConf.Args, [2]string{"LinkMTUOverhead", overhead})
	}
	if mac := state.Config.Labels["io.rancher.container.mac_address"]; mac != "" {
		c.runtimeConf.Args = append(c.runtimeConf.Args, [2]string{"MACAddress", mac})
	}

	networkName := state.HostConfig.NetworkMode.NetworkName()
	if networkName == "" {
		networkName = "default"
	}
	files, err := libcni.ConfFiles(fmt.Sprintf(CniDir, networkName), []string{".conf", ".json"})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if err := os.Setenv("PATH", strings.Join(CniPath, string(os.PathListSeparator))); err != nil {
		return nil, fmt.Errorf("set CNI plugin path: %w", err)
	}
	for _, file := range files {
		conf, err := libcni.ConfFromFile(file)
		if err != nil {
			return nil, err
		}
		c.confs = append(c.confs, conf)
	}
	return c, nil
}

func CNIAdd(state *DockerPluginState) (*types100.Result, error) {
	c, err := NewCNIExec(state)
	if err != nil {
		return nil, err
	}
	var result *types100.Result
	for index := range c.confs {
		pluginResult, err := c.Add(index)
		if err != nil {
			return nil, err
		}
		if PrimaryIPv4(pluginResult) != "" {
			result = pluginResult
		}
	}
	return result, nil
}

func CNIDel(state *DockerPluginState) error {
	c, err := NewCNIExec(state)
	if err != nil {
		return err
	}
	var lastErr error
	for index := len(c.confs) - 1; index >= 0; index-- {
		if err := c.Del(index); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func PrimaryIPv4(result *types100.Result) string {
	if result == nil {
		return ""
	}
	for _, config := range result.IPs {
		if config != nil && config.Address.IP != nil && config.Address.IP.To4() != nil {
			return net.IP(config.Address.IP).String()
		}
	}
	return ""
}
