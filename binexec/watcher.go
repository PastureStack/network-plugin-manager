package binexec

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/docker/engine-api/client"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/rancher/cniglue"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery = 5 * time.Minute
	binDir       = glue.CniPath[0]
)

func Watch(c metadata.Client, dc *client.Client) *Watcher {
	w := &Watcher{
		c:       c,
		dc:      dc,
		applied: map[string]string{},
	}
	w.onChange("")
	go c.OnChange(5, w.onChangeNoError)
	return w
}

type Watcher struct {
	sync.Mutex
	c           metadata.Client
	dc          *client.Client
	applied     map[string]string
	lastApplied time.Time
}

func (w *Watcher) onChangeNoError(version string) {
	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to apply cni conf: %v", err)
	}
}

func (w *Watcher) Handle(event *docker.APIEvents) error {
	w.Lock()

	changed := false
	for _, v := range w.applied {
		if v == event.ID {
			changed = true
			break
		}
	}

	w.lastApplied = time.Time{}
	w.Unlock()

	if changed {
		return w.onChange("")
	}
	return nil
}

func (w *Watcher) onChange(version string) error {
	w.Lock()
	defer w.Unlock()

	binaries := map[string]string{}
	driverServices := map[string]metadata.Service{}

	services, err := w.c.GetServices()
	if err != nil {
		return err
	}

	hostUUID, err := identity.LocalHostUUID(w.c, w.dc)
	if err != nil {
		return err
	}

	for _, service := range services {
		if service.Kind != "networkDriverService" && service.Kind != "storageDriverService" {
			continue
		}

		driverServices[service.StackUUID+"/"+service.Name] = service
	}

	for _, service := range services {
		if _, ok := driverServices[service.StackUUID+"/"+service.PrimaryServiceName]; ok {
			driverServices[service.StackUUID+"/"+service.Name] = service
		}
	}

	for _, service := range driverServices {
		for _, container := range service.Containers {
			logrus.WithFields(logrus.Fields{
				"serviceKind":         service.Kind,
				"serviceName":         service.Name,
				"containerName":       container.Name,
				"containerExternalId": container.ExternalId,
				"containerHostUUID":   container.HostUUID,
				"driverLabel":         hasDriverLabel(container),
			}).Debugf("Checking for driver binary")
			if container.ExternalId != "" && container.HostUUID == hostUUID && hasDriverLabel(container) {
				binName := getBinaryName(container)
				if binName != "" {
					binaries[binName] = container.ExternalId
				}
			}
		}
	}

	if time.Now().Sub(w.lastApplied) > reapplyEvery || !reflect.DeepEqual(binaries, w.applied) {
		return w.apply(binaries)
	}

	return nil
}

func (w *Watcher) apply(binaries map[string]string) error {
	if !reflect.DeepEqual(binaries, w.applied) {
		logrus.Infof("Setting up binaries for: %v", binaries)
	}

	script := `#!/bin/sh
target="%s"
service_label="%s"
cid=""
if [ -n "${service_label}" ]; then
    cid="$(docker ps -q --filter "label=io.rancher.stack_service.name=${service_label}" | head -n 1)"
fi
if [ -z "${cid}" ]; then
    cid="${target}"
fi
pid="$(docker inspect -f '{{.State.Pid}}' "${cid}" 2>/dev/null || true)"
if [ -z "${pid}" ] || [ "${pid}" = "0" ]; then
    echo "{\"code\":100,\"msg\":\"cni driver container not running: ${service_label:-${target}}\"}" >&2
    exit 1
fi
exec /usr/bin/nsenter -m -u -i -n -p -t "${pid}" -- $0 "$@"
`

	os.MkdirAll(binDir, 0700)

	var lastErr error
	for name, target := range binaries {
		container, err := w.dc.ContainerInspect(context.Background(), target)
		if err != nil {
			lastErr = err
			break
		}

		if container.State == nil || container.State.Pid == 0 {
			lastErr = fmt.Errorf("container is not running")
			break
		}

		serviceLabel := ""
		if container.Config != nil && container.Config.Labels != nil {
			serviceLabel = container.Config.Labels["io.rancher.stack_service.name"]
		}

		ptmp := filepath.Join(binDir, name+".tmp")
		p := filepath.Join(binDir, name)
		content := []byte(fmt.Sprintf(script, target, serviceLabel))
		logrus.Debugf("Writing %s:\n%s", p, content)
		if err := ioutil.WriteFile(ptmp, content, 0700); err != nil {
			lastErr = err
			break
		}

		if err := os.Rename(ptmp, p); err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		w.applied = binaries
		w.lastApplied = time.Now()
	}

	return lastErr
}

func getBinaryName(container metadata.Container) string {
	return container.Labels["io.rancher.network.cni.binary"]
}

func hasDriverLabel(container metadata.Container) bool {
	return "" != container.Labels["io.rancher.network.cni.binary"]
}
