package binexec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

// IDs preserve the observed old-before-new ordering without private host data.
const oldDriverID = "0000000000000000000000000000000000000000000000000000000000000038"
const newDriverID = "1000000000000000000000000000000000000000000000000000000000000040"
const driverBinary = "pasture-bridge"

type lifecycleMetadata struct {
	metadata.Client
	services []metadata.Service
	err      error
	calls    int
}

func (m *lifecycleMetadata) GetServices() ([]metadata.Service, error) {
	m.calls++
	return m.services, m.err
}

func (m *lifecycleMetadata) GetSelfHost() (metadata.Host, error) {
	return metadata.Host{UUID: "local-host"}, nil
}

type dockerProvider struct {
	version string
	running bool
	pid     int
	status  int
	delay   time.Duration
}

func lifecycleFixture(t *testing.T) (*Watcher, *lifecycleMetadata, map[string]dockerProvider) {
	t.Helper()
	previous := binDir
	binDir = t.TempDir()
	t.Cleanup(func() { binDir = previous })
	providers := map[string]dockerProvider{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/json") {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1.55/containers/"), "/json")
		provider, found := providers[id]
		if !found {
			http.NotFound(w, r)
			return
		}
		if provider.delay > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(provider.delay):
			}
		}
		if provider.status != 0 {
			http.Error(w, "temporary inspect failure", provider.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":     id,
			"Config": map[string]interface{}{"Labels": map[string]string{"org.opencontainers.image.version": provider.version}},
			"State":  map[string]interface{}{"Running": provider.running, "Pid": provider.pid},
		})
	}))
	t.Cleanup(server.Close)
	docker, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = docker.Close() })
	m := &lifecycleMetadata{}
	return &Watcher{c: m, dc: docker, applied: map[string]string{}}, m, providers
}

func localDriver(id, name string) metadata.Container {
	return metadata.Container{ExternalId: id, HostUUID: "local-host", Labels: map[string]string{"io.rancher.network.cni.binary": name}}
}

func driverServices(containers ...metadata.Container) []metadata.Service {
	return []metadata.Service{{Kind: "networkDriverService", StackUUID: "stack", Name: "driver", Containers: containers}}
}

func assertSelected(t *testing.T, w *Watcher, name, id string) {
	t.Helper()
	if got := w.applied[name]; got != id {
		t.Fatalf("selected %s provider = %q, want %q", name, got, id)
	}
	data, err := os.ReadFile(filepath.Join(binDir, name))
	if err != nil || !strings.Contains(string(data), "target='"+id+"'") {
		t.Fatalf("wrapper does not use selected provider: %s, %v", data, err)
	}
}

func TestProviderStartReselects40AfterSelected38Stops(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	m.services = driverServices(localDriver(oldDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	providers[oldDriverID] = dockerProvider{version: "0.14.38"}
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	m.services = driverServices(localDriver(oldDriverID, driverBinary), localDriver(newDriverID, driverBinary))
	if err := w.Handle(&events.Message{Action: events.ActionStart, Actor: events.Actor{ID: newDriverID, Attributes: map[string]string{"io.rancher.network.cni.binary": driverBinary}}}); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, w, driverBinary, newDriverID)
}

func TestStoppedNewerProviderCannotDisplaceRunningProvider(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-first", true: "new-first"}[reversed], func(t *testing.T) {
			w, m, providers := lifecycleFixture(t)
			providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
			providers[newDriverID] = dockerProvider{version: "0.14.40"}
			candidates := []metadata.Container{localDriver(oldDriverID, driverBinary), localDriver(newDriverID, driverBinary)}
			if reversed {
				candidates[0], candidates[1] = candidates[1], candidates[0]
			}
			m.services = driverServices(candidates...)
			if err := w.onChange(""); err != nil {
				t.Fatal(err)
			}
			assertSelected(t, w, driverBinary, oldDriverID)
		})
	}
}

func TestApplyFailureDoesNotBlockIndependentBinary(t *testing.T) {
	w, _, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38"}
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	if err := w.apply(map[string]string{"stopped-driver": oldDriverID, driverBinary: newDriverID}); err == nil {
		t.Fatal("stopped provider failure was hidden")
	}
	assertSelected(t, w, driverBinary, newDriverID)
}

func TestInspectFailureIsVisibleAndHealthySelectionRecovers(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	m.services = driverServices(localDriver(oldDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	providers[newDriverID] = dockerProvider{status: http.StatusServiceUnavailable}
	m.services = driverServices(localDriver(oldDriverID, driverBinary), localDriver(newDriverID, driverBinary))
	if err := w.onChange(""); err == nil {
		t.Fatal("candidate inspection failure was silently treated as a missing version")
	}
	assertSelected(t, w, driverBinary, oldDriverID)
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, w, driverBinary, newDriverID)
}

func TestMetadataFailurePreservesSelectionUntilRecovery(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	m.services = driverServices(localDriver(oldDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	m.err = errors.New("metadata temporarily unavailable")
	if err := w.onChange(""); err == nil {
		t.Fatal("metadata error was hidden")
	}
	assertSelected(t, w, driverBinary, oldDriverID)
	m.err = nil
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	m.services = driverServices(localDriver(oldDriverID, driverBinary), localDriver(newDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, w, driverBinary, newDriverID)
}

func TestSelectedDriverDieDoesNotRemoveIndependentDriver(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	m.services = driverServices(localDriver(oldDriverID, "retiring-driver"), localDriver(newDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	providers[oldDriverID] = dockerProvider{version: "0.14.38"}
	if err := w.Handle(&events.Message{Action: events.ActionDie, Actor: events.Actor{ID: oldDriverID}}); err == nil {
		t.Fatal("unavailable retiring provider was not reported")
	}
	assertSelected(t, w, driverBinary, newDriverID)
	if _, found := w.applied["retiring-driver"]; found {
		t.Fatal("known stopped provider remains selected")
	}
	if _, err := os.Lstat(filepath.Join(binDir, "retiring-driver")); !os.IsNotExist(err) {
		t.Fatalf("unavailable owned wrapper was not retired: %v", err)
	}
	calls := m.calls
	if err := w.Handle(&events.Message{Action: events.ActionDie, Actor: events.Actor{ID: "unrelated"}}); err != nil || m.calls != calls {
		t.Fatal("unrelated container death caused provider reconfiguration")
	}
}

func TestProviderSelectionPreservesMetadataHostAndRoleAllowlist(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	remote := localDriver(newDriverID, driverBinary)
	remote.HostUUID = "other-host"
	m.services = append(driverServices(localDriver(oldDriverID, driverBinary), remote), metadata.Service{
		Kind: "service", StackUUID: "unrelated-stack", Name: "not-a-driver", Containers: []metadata.Container{localDriver(newDriverID, driverBinary)},
	})
	if err := w.Handle(&events.Message{Action: events.ActionStart, Actor: events.Actor{ID: newDriverID, Attributes: map[string]string{"io.rancher.network.cni.binary": driverBinary}}}); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, w, driverBinary, oldDriverID)
}

func TestProviderRequiresBothRunningAndPositivePID(t *testing.T) {
	for _, bad := range []dockerProvider{{version: "0.14.40", pid: 40}, {version: "0.14.40", running: true}} {
		w, m, providers := lifecycleFixture(t)
		providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
		providers[newDriverID] = bad
		m.services = driverServices(localDriver(newDriverID, driverBinary), localDriver(oldDriverID, driverBinary))
		if err := w.onChange(""); err != nil {
			t.Fatal(err)
		}
		assertSelected(t, w, driverBinary, oldDriverID)
	}
}

func TestPeriodicRefreshReselectsWithoutMetadataVersionOrWrapperDrift(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	m.services = driverServices(localDriver(oldDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	// A failed callback is followed by no metadata version change or Docker
	// event. The existing wrapper is intact, so drift-only refresh cannot help.
	m.err = errors.New("one failed metadata callback")
	if err := w.onChange("unchanged-version"); err == nil {
		t.Fatal("callback failure was hidden")
	}
	m.err = nil
	providers[oldDriverID] = dockerProvider{version: "0.14.38"}
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40}
	m.services = driverServices(localDriver(oldDriverID, driverBinary), localDriver(newDriverID, driverBinary))
	if !w.wrapperFilesMatch(w.applied) {
		t.Fatal("fixture unexpectedly has wrapper drift")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); w.refreshProviders(ctx, ticks) }()
	ticks <- time.Now()
	deadline := time.After(2 * time.Second)
	for {
		w.Lock()
		selected := w.applied[driverBinary]
		w.Unlock()
		if selected == newDriverID {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("periodic refresh did not recover selection")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	assertSelected(t, w, driverBinary, newDriverID)
}

func TestCandidateInspectionHasBoundedDeadline(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	previous := providerInspectTimeout
	providerInspectTimeout = 20 * time.Millisecond
	defer func() { providerInspectTimeout = previous }()
	providers[newDriverID] = dockerProvider{version: "0.14.40", running: true, pid: 40, delay: time.Second}
	m.services = driverServices(localDriver(newDriverID, driverBinary))
	started := time.Now()
	if err := w.onChange(""); err == nil {
		t.Fatal("inspect deadline was hidden")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("inspect was not bounded by its context deadline")
	}
	if len(w.applied) != 0 {
		t.Fatal("uninspected candidate was selected")
	}
}

func TestInspectNotFoundRetiresButUnknownPreservesAuthorizedSelection(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			w, m, providers := lifecycleFixture(t)
			providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
			m.services = driverServices(localDriver(oldDriverID, driverBinary))
			if err := w.onChange(""); err != nil {
				t.Fatal(err)
			}
			providers[oldDriverID] = dockerProvider{status: status}
			if err := w.Handle(&events.Message{Action: events.ActionDie, Actor: events.Actor{ID: oldDriverID}}); err == nil {
				t.Fatal("inspect error was hidden")
			}
			if status == http.StatusServiceUnavailable {
				assertSelected(t, w, driverBinary, oldDriverID)
			} else if w.applied[driverBinary] != "" {
				t.Fatal("authoritatively absent provider remains selected")
			} else if _, err := os.Lstat(filepath.Join(binDir, driverBinary)); !os.IsNotExist(err) {
				t.Fatalf("absent provider's owned wrapper remains: %v", err)
			}
		})
	}
}

func TestUnknownInspectionCannotRetainRevokedBinaryName(t *testing.T) {
	w, m, providers := lifecycleFixture(t)
	providers[oldDriverID] = dockerProvider{version: "0.14.38", running: true, pid: 38}
	m.services = driverServices(localDriver(oldDriverID, driverBinary))
	if err := w.onChange(""); err != nil {
		t.Fatal(err)
	}
	providers[oldDriverID] = dockerProvider{status: http.StatusServiceUnavailable}
	m.services = driverServices(localDriver(oldDriverID, "different-binary"))
	if err := w.onChange(""); err == nil {
		t.Fatal("inspect error was hidden")
	}
	if w.applied[driverBinary] != "" {
		t.Fatal("same container's unknown state retained a revoked binary authorization")
	}
}
