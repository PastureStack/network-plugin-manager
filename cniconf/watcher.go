package cniconf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/cniglue"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery = 5 * time.Minute
	cniDir       = "/etc/cni/%s.d"
)

func init() {
	cniglue.CniDir = cniDir
}

func Watch(c metadata.Client, dc *client.Client) error {
	w := &watcher{
		c:       c,
		dc:      dc,
		applied: map[string]metadata.Network{},
	}
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

type watcher struct {
	c           metadata.Client
	dc          *client.Client
	applied     map[string]metadata.Network
	lastApplied time.Time
}

func (w *watcher) onChangeNoError(version string) {
	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to apply cni conf: %v", err)
	}
}

func (w *watcher) onChange(version string) error {
	networks, err := w.c.GetNetworks()
	if err != nil {
		return err
	}

	hostUUID, err := identity.LocalHostUUID(w.c, w.dc)
	if err != nil {
		return err
	}

	services, err := w.c.GetServices()
	if err != nil {
		return err
	}

	localNetworks := localCNINetworks(networks, services, hostUUID)
	logrus.Debugf("localNetworks: %v", localNetworks)

	forceApply := time.Now().Sub(w.lastApplied) > reapplyEvery
	var applyErrors []error

	for _, network := range networks {
		if _, local := localNetworks[network.UUID]; !local {
			logrus.Debugf("network: %v is not local to this environment", network.UUID)
			continue
		}
		_, ok := network.Metadata["cniConfig"].(map[string]interface{})
		if !ok {
			continue
		}

		if forceApply || !reflect.DeepEqual(w.applied[network.Name], network) {
			if err := w.apply(network); err != nil {
				applyErrors = append(applyErrors, fmt.Errorf("network %q: %w", network.Name, err))
			}
		}
	}

	return errors.Join(applyErrors...)
}

// localCNINetworks returns the CNI-managed networks that must be configured on
// this host. Network driver services run in the host network namespace, so the
// driver's container NetworkUUID identifies the host network rather than the
// managed overlay network. A local network driver therefore owns every network
// that advertises a cniConfig in metadata.
func localCNINetworks(networks []metadata.Network, services []metadata.Service, hostUUID string) map[string]bool {
	result := map[string]bool{}
	hasLocalNetworkDriver := false
	for _, service := range services {
		if service.Kind != "networkDriverService" {
			continue
		}
		for _, aContainer := range service.Containers {
			if aContainer.HostUUID == hostUUID {
				hasLocalNetworkDriver = true
				break
			}
		}
		if hasLocalNetworkDriver {
			break
		}
	}

	if !hasLocalNetworkDriver {
		return result
	}
	for _, network := range networks {
		if _, ok := network.Metadata["cniConfig"].(map[string]interface{}); ok {
			result[network.UUID] = true
		}
	}
	return result
}

func (w *watcher) apply(network metadata.Network) error {
	return w.applyWithWriter(network, writeConfigAtomic)
}

func (w *watcher) applyWithWriter(network metadata.Network, writeConfig func(string, []byte) error) error {
	cniConf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	if !validConfigName(network.Name) {
		return fmt.Errorf("invalid CNI network name %q", network.Name)
	}
	confDir := fmt.Sprintf(cniDir, network.Name)
	files, err := prepareConfigFiles(confDir, cniConf)
	if err != nil {
		return err
	}
	retirement, err := prepareLegacyRetirement(confDir, files)
	if err != nil {
		return err
	}
	if err := ensureConfigDirectory(confDir); err != nil {
		return err
	}
	for _, file := range files {
		logrus.Debugf("Writing CNI config %s", file.path)
		if err := writeConfig(file.path, file.content); err != nil {
			return err
		}
	}

	if network.Default {
		managedDir := fmt.Sprintf(cniDir, "managed")
		managedDirTest, err := os.Stat(managedDir)
		configDirTest, err1 := os.Stat(confDir)
		if !(err == nil && err1 == nil && os.SameFile(managedDirTest, configDirTest)) {
			if err := replaceManagedSymlink(managedDir, network.Name+".d"); err != nil {
				return err
			}
		}
	}

	if err := retirement.retire(); err != nil {
		return err
	}
	if retirement != nil {
		logrus.Infof("Retired superseded platform CNI config %s; recoverable copy: %s", retirement.path, retirement.backup)
	}
	w.applied[network.Name] = network
	w.lastApplied = time.Now()

	return nil
}
