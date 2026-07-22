package cniconf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/docker/engine-api/client"
	"github.com/rancher/cniglue"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery = 5 * time.Minute
	cniDir       = "/etc/cni/%s.d"
)

func init() {
	glue.CniDir = cniDir
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

	localNetworks := map[string]bool{}
	for _, service := range services {
		if service.Kind != "networkDriverService" {
			continue
		}

		for _, aContainer := range service.Containers {
			if aContainer.HostUUID == hostUUID {
				localNetworks[aContainer.NetworkUUID] = true
			}
		}
	}
	logrus.Debugf("localNetworks: %v", localNetworks)

	forceApply := time.Now().Sub(w.lastApplied) > reapplyEvery

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
				logrus.Errorf("Failed to apply cni conf: %v", err)
			}
		}
	}

	return nil
}

func (w *watcher) apply(network metadata.Network) error {
	cniConf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	confDir := fmt.Sprintf(cniDir, network.Name)
	if err := os.MkdirAll(confDir, 0700); err != nil {
		return err
	}

	var lastErr error
	for file, config := range cniConf {
		p := filepath.Join(confDir, file)
		content, err := json.Marshal(config)
		if err != nil {
			lastErr = err
			continue
		}

		out := &bytes.Buffer{}
		if err := json.Indent(out, content, "", "  "); err != nil {
			lastErr = err
			continue
		}

		logrus.Debugf("Writing %s: %s", p, out)
		if err := ioutil.WriteFile(p, out.Bytes(), 0600); err != nil {
			lastErr = err
		}
	}

	if network.Default {
		managedDir := fmt.Sprintf(cniDir, "managed")
		managedDirTest, err := os.Stat(managedDir)
		configDirTest, err1 := os.Stat(confDir)
		if !(err == nil && err1 == nil && os.SameFile(managedDirTest, configDirTest)) {
			os.Remove(managedDir)
			if err := os.Symlink(network.Name+".d", managedDir); err != nil {
				lastErr = err
			}
		}
	}

	if lastErr == nil {
		w.applied[network.Name] = network
		w.lastApplied = time.Now()
	}

	return lastErr
}
