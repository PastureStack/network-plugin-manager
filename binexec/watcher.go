package binexec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/cniglue"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery = 5 * time.Minute
	binDir       = cniglue.CniPath[0]
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

func (w *Watcher) Handle(event *events.Message) error {
	w.Lock()

	changed := false
	for _, v := range w.applied {
		if v == event.Actor.ID {
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

	const script = `#!/bin/sh
set -eu
target=%s
service_label=%s
socket=/var/run/docker.sock
api_prefix=""
if [ -n "${DOCKER_API_VERSION:-}" ]; then
    case "${DOCKER_API_VERSION}" in
        *[!0-9.]*|'') echo '{"code":100,"msg":"invalid Docker API version"}' >&2; exit 1 ;;
    esac
    api_prefix="/v${DOCKER_API_VERSION}"
fi
cid=""
if [ -n "${service_label}" ]; then
    filters="$(jq -cn --arg label "io.rancher.stack_service.name=${service_label}" '{label:[$label]}')"
    cid="$(curl -fsS --max-time 10 --unix-socket "${socket}" --get \
        --data-urlencode "filters=${filters}" \
        "http://localhost${api_prefix}/containers/json" | jq -r '.[0].Id // empty')"
fi
if [ -z "${cid}" ]; then
    cid="${target}"
fi
case "${cid}" in
    *[!0-9a-fA-F]*|'') echo '{"code":100,"msg":"invalid CNI driver container id"}' >&2; exit 1 ;;
esac
pid="$(curl -fsS --max-time 10 --unix-socket "${socket}" \
    "http://localhost${api_prefix}/containers/${cid}/json" | jq -r '.State.Pid // 0' || true)"
if [ -z "${pid}" ] || [ "${pid}" = "0" ]; then
    echo "{\"code\":100,\"msg\":\"cni driver container not running: ${service_label:-${target}}\"}" >&2
    exit 1
fi
exec /usr/bin/nsenter -m -u -i -n -p -t "${pid}" -- $0 "$@"
`

	os.MkdirAll(binDir, 0700)

	var lastErr error
	for name, target := range binaries {
		inspectResult, err := w.dc.ContainerInspect(context.Background(), target, client.ContainerInspectOptions{})
		if err != nil {
			lastErr = err
			break
		}

		container := inspectResult.Container
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
		content := []byte(fmt.Sprintf(script, shellQuote(target), shellQuote(serviceLabel)))
		logrus.Debugf("Writing %s:\n%s", p, content)
		if err := os.WriteFile(ptmp, content, 0700); err != nil {
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

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func getBinaryName(container metadata.Container) string {
	return container.Labels["io.rancher.network.cni.binary"]
}

func hasDriverLabel(container metadata.Container) bool {
	return "" != container.Labels["io.rancher.network.cni.binary"]
}
