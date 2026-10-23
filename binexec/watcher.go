package binexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/cniglue"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery           = 5 * time.Minute
	wrapperDriftCheckEvery = 10 * time.Second
	providerInspectTimeout = 10 * time.Second
	binDir                 = cniglue.CniPath[0]
)

const driverWrapperScript = `#!/bin/sh
set -eu
target=%s
binary_name=%s
socket=/var/run/docker.sock
api_prefix=""
if [ -n "${DOCKER_API_VERSION:-}" ]; then
    case "${DOCKER_API_VERSION}" in
        *[!0-9.]*|'') echo '{"code":100,"msg":"invalid Docker API version"}' >&2; exit 1 ;;
    esac
    api_prefix="/v${DOCKER_API_VERSION}"
fi
case "${target}" in
    *[!0-9a-fA-F]*|'') echo '{"code":100,"msg":"invalid CNI driver container id"}' >&2; exit 1 ;;
esac
pid="$(curl -fsS --max-time 10 --unix-socket "${socket}" \
    "http://localhost${api_prefix}/containers/${target}/json" | jq -r '.State.Pid // 0' || true)"
case "${pid}" in
    ''|0|*[!0-9]*)
    echo "{\"code\":100,\"msg\":\"selected cni driver container not running: ${target}\"}" >&2
    exit 1
    ;;
esac
private_binary="/opt/cni/bin/${binary_name}"
if /usr/bin/nsenter -m -u -i -n -p -t "${pid}" -- test -x "${private_binary}"; then
    exec /usr/bin/nsenter -m -u -i -n -p -t "${pid}" -- \
        /usr/bin/env CNI_PATH=/opt/cni/bin "${private_binary}" "$@"
fi
exec /usr/bin/nsenter -m -u -i -n -p -t "${pid}" -- "$0" "$@"
`

func Watch(c metadata.Client, dc *client.Client) *Watcher {
	w := &Watcher{
		c:       c,
		dc:      dc,
		applied: map[string]string{},
	}
	w.onChangeNoError("")
	go c.OnChange(5, w.onChangeNoError)
	go w.watchWrapperDrift()
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

func (w *Watcher) watchWrapperDrift() {
	ticker := time.NewTicker(wrapperDriftCheckEvery)
	defer ticker.Stop()
	w.refreshProviders(context.Background(), ticker.C)
}

// Retry selection even when metadata's version and the wrapper bytes have not
// changed: a driver can become ready after an earlier inspect/apply failure.
func (w *Watcher) refreshProviders(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			w.onChangeNoError("")
		}
	}
}

func (w *Watcher) Handle(event *events.Message) error {
	if event == nil {
		return nil
	}
	w.Lock()

	changed := false
	for _, v := range w.applied {
		if v == event.Actor.ID {
			changed = true
			break
		}
	}

	// A newly started driver is not in applied yet. Its event is only a reason
	// to re-read the metadata allowlist, never permission to use a Docker-only
	// provider. Ordinary workload starts must not trigger provider selection.
	if event.Action == events.ActionStart && validBinaryName(event.Actor.Attributes["io.rancher.network.cni.binary"]) {
		changed = true
	}
	if changed {
		w.lastApplied = time.Time{}
	}
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
	versions := map[string]string{}
	uncertain := map[string]map[string]bool{}
	availableNames := map[string]bool{}
	var selectionErrors []error
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
					if !validBinaryName(binName) {
						selectionErrors = append(selectionErrors, fmt.Errorf("invalid CNI driver binary name %q", binName))
						continue
					}
					availableNames[binName] = true
					inspectResult, err := w.inspectProvider(container.ExternalId)
					if err != nil {
						// NotFound is authoritative absence, not an unknown state
						// eligible to preserve an old selected wrapper.
						if !errdefs.IsNotFound(err) {
							if uncertain[binName] == nil {
								uncertain[binName] = map[string]bool{}
							}
							uncertain[binName][container.ExternalId] = true
						}
						selectionErrors = append(selectionErrors, fmt.Errorf("inspect CNI provider %s for %s: %w", container.ExternalId, binName, err))
						continue
					}
					provider := inspectResult.Container
					if provider.State == nil || !provider.State.Running || provider.State.Pid <= 0 {
						continue
					}
					version := ""
					if provider.Config != nil {
						version = strings.TrimSpace(provider.Config.Labels["org.opencontainers.image.version"])
					}
					current, exists := binaries[binName]
					if !exists || preferProvider(current, versions[binName], container.ExternalId, version) {
						binaries[binName] = container.ExternalId
						versions[binName] = version
					}
				}
			}
		}
	}
	// Preserve an existing metadata-authorized provider on an unknown inspect
	// result, but never retain one Docker has authoritatively reported stopped.
	for name, target := range w.applied {
		if binaries[name] == "" && uncertain[name][target] {
			binaries[name] = target
		}
	}
	for name := range availableNames {
		if binaries[name] == "" {
			selectionErrors = append(selectionErrors, fmt.Errorf("no running metadata-authorized CNI provider for %s", name))
		}
	}

	needsApply := time.Now().Sub(w.lastApplied) > reapplyEvery || !reflect.DeepEqual(binaries, w.applied)
	if !needsApply && !w.wrapperFilesMatch(binaries) {
		logrus.Warn("CNI driver wrapper drift detected; restoring selected providers")
		needsApply = true
	}
	if needsApply {
		selectionErrors = append(selectionErrors, w.apply(binaries))
	}

	return errors.Join(selectionErrors...)
}

func (w *Watcher) wrapperFilesMatch(binaries map[string]string) bool {
	for name, target := range binaries {
		expected := renderDriverWrapper(target, name)
		if !wrapperFileMatches(filepath.Join(binDir, name), expected) {
			return false
		}
	}
	return true
}

func wrapperFileMatches(path string, expected []byte) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0700 {
		return false
	}
	actual, err := os.ReadFile(path)
	return err == nil && bytes.Equal(actual, expected)
}

func (w *Watcher) apply(binaries map[string]string) error {
	if !reflect.DeepEqual(binaries, w.applied) {
		logrus.Infof("Setting up binaries for: %v", binaries)
	}

	if err := os.MkdirAll(binDir, 0700); err != nil {
		return fmt.Errorf("create CNI wrapper directory: %w", err)
	}

	var applyErrors []error
	unavailable := map[string]bool{}
	updated := make(map[string]string, len(w.applied))
	for name, target := range w.applied {
		updated[name] = target
	}
	for name, target := range binaries {
		inspectResult, err := w.inspectProvider(target)
		if err != nil {
			if errdefs.IsNotFound(err) && updated[name] == target {
				unavailable[name] = true
			}
			applyErrors = append(applyErrors, fmt.Errorf("inspect selected CNI provider %s for %s: %w", target, name, err))
			continue
		}

		container := inspectResult.Container
		if container.State == nil || !container.State.Running || container.State.Pid <= 0 {
			if updated[name] == target {
				unavailable[name] = true
			}
			applyErrors = append(applyErrors, fmt.Errorf("CNI provider %s for %s is not running", target, name))
			continue
		}

		p := filepath.Join(binDir, name)
		content := renderDriverWrapper(target, name)
		logrus.Debugf("Writing %s:\n%s", p, content)
		if err := writeWrapperAtomic(p, content); err != nil {
			applyErrors = append(applyErrors, err)
			continue
		}
		updated[name] = target
	}

	for name, target := range w.applied {
		if _, retained := binaries[name]; retained && !unavailable[name] {
			continue
		}
		// Remove only this watcher's exact wrapper; do not unlink another owner's
		// file or disturb independent providers when a driver is unavailable.
		p := filepath.Join(binDir, name)
		if wrapperFileMatches(p, renderDriverWrapper(target, name)) {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				applyErrors = append(applyErrors, fmt.Errorf("remove unavailable CNI provider wrapper %s: %w", name, err))
				continue
			}
		}
		delete(updated, name)
	}
	w.applied = updated
	if len(applyErrors) == 0 {
		w.lastApplied = time.Now()
	}

	return errors.Join(applyErrors...)
}

func (w *Watcher) inspectProvider(target string) (client.ContainerInspectResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), providerInspectTimeout)
	defer cancel()
	return w.dc.ContainerInspect(ctx, target, client.ContainerInspectOptions{})
}

func preferProvider(current, currentVersion, candidate, candidateVersion string) bool {
	comparison, comparable := compareNumericVersions(candidateVersion, currentVersion)
	if comparable && comparison != 0 {
		return comparison > 0
	}
	_, currentNumeric := numericVersionParts(currentVersion)
	_, candidateNumeric := numericVersionParts(candidateVersion)
	if currentNumeric != candidateNumeric {
		return candidateNumeric
	}
	return candidate < current
}

func writeWrapperAtomic(path string, content []byte) (err error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create private CNI wrapper temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write private CNI wrapper temporary file: %w", err)
	}
	if err := temporary.Chmod(0700); err != nil {
		return fmt.Errorf("set private CNI wrapper permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync private CNI wrapper temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private CNI wrapper temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install private CNI wrapper: %w", err)
	}
	committed = true
	return nil
}

func renderDriverWrapper(target, name string) []byte {
	return []byte(fmt.Sprintf(driverWrapperScript, shellQuote(target), shellQuote(name)))
}

func compareNumericVersions(left, right string) (int, bool) {
	leftParts, leftOK := numericVersionParts(left)
	rightParts, rightOK := numericVersionParts(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	for index := 0; index < len(leftParts) || index < len(rightParts); index++ {
		leftValue, rightValue := 0, 0
		if index < len(leftParts) {
			leftValue = leftParts[index]
		}
		if index < len(rightParts) {
			rightValue = rightParts[index]
		}
		if leftValue < rightValue {
			return -1, true
		}
		if leftValue > rightValue {
			return 1, true
		}
	}
	return 0, true
}

func numericVersionParts(value string) ([]int, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if value == "" {
		return nil, false
	}
	parts := strings.Split(value, ".")
	parsed := make([]int, len(parts))
	for index, part := range parts {
		if part == "" {
			return nil, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, false
		}
		parsed[index] = value
	}
	return parsed, true
}

func validBinaryName(value string) bool {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/\\`) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
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
