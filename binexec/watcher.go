package binexec

import (
	"bytes"
	"context"
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
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

var (
	reapplyEvery           = 5 * time.Minute
	wrapperDriftCheckEvery = 10 * time.Second
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
	w.onChange("")
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
	for range ticker.C {
		w.Lock()
		if len(w.applied) != 0 && !w.wrapperFilesMatch(w.applied) {
			logrus.Warn("CNI driver wrapper drift detected; restoring selected providers")
			if err := w.apply(w.applied); err != nil {
				logrus.Errorf("Failed to restore CNI driver wrappers: %v", err)
			}
		}
		w.Unlock()
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
					if !validBinaryName(binName) {
						return fmt.Errorf("invalid CNI driver binary name %q", binName)
					}
					current, exists := binaries[binName]
					if !exists || w.preferBinaryProvider(current, container.ExternalId) {
						binaries[binName] = container.ExternalId
					}
				}
			}
		}
	}

	needsApply := time.Now().Sub(w.lastApplied) > reapplyEvery || !reflect.DeepEqual(binaries, w.applied)
	if !needsApply && !w.wrapperFilesMatch(binaries) {
		logrus.Warn("CNI driver wrapper drift detected; restoring selected providers")
		needsApply = true
	}
	if needsApply {
		return w.apply(binaries)
	}

	return nil
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

		p := filepath.Join(binDir, name)
		content := renderDriverWrapper(target, name)
		logrus.Debugf("Writing %s:\n%s", p, content)
		if err := writeWrapperAtomic(p, content); err != nil {
			lastErr = err
			break
		}
	}

	if lastErr == nil {
		w.applied = binaries
		w.lastApplied = time.Now()
	}

	return lastErr
}

func (w *Watcher) preferBinaryProvider(current, candidate string) bool {
	currentVersion := w.containerImageVersion(current)
	candidateVersion := w.containerImageVersion(candidate)
	return preferProvider(current, currentVersion, candidate, candidateVersion)
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

func (w *Watcher) containerImageVersion(containerID string) string {
	if w.dc == nil {
		return ""
	}
	result, err := w.dc.ContainerInspect(context.Background(), containerID, client.ContainerInspectOptions{})
	if err != nil || result.Container.Config == nil || result.Container.Config.Labels == nil {
		return ""
	}
	return strings.TrimSpace(result.Container.Config.Labels["org.opencontainers.image.version"])
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
