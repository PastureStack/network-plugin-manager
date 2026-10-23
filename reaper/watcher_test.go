package reaper

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/moby/moby/client"
)

func TestReaperPreservesManagedDependenciesDuringReplacement(t *testing.T) {
	var removed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Query().Get("force") != "1" {
			t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
		}
		removed = append(removed, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dc, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.44"))
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	makeContainer := func(id, label string) metadata.Container {
		return metadata.Container{
			UUID: id, ExternalId: id, HostUUID: "local",
			Labels: map[string]string{uuidLabel: "different-uuid", serviceNameLabel: label},
		}
	}
	containers := []metadata.Container{
		makeContainer("metadata-old", metadataService),
		makeContainer("metadata-new", metadataService),
		makeContainer("dns-old", dnsService),
		makeContainer("dns-new", dnsService),
		makeContainer("metadata-without-label", ""),
		makeContainer("dns-without-label", ""),
		makeContainer("other-host", "other/workload"),
		makeContainer("matching-uuid", "other/workload"),
		{UUID: "unmanaged-label", HostUUID: "local", ExternalId: "unmanaged-label"},
		makeContainer("orphan", "other/workload"),
	}
	containers[4].StackName, containers[4].ServiceName = "network-services", "metadata"
	containers[5].StackName, containers[5].ServiceName = "network-services", "dns"
	containers[6].HostUUID = "remote"
	containers[7].Labels[uuidLabel] = containers[7].UUID
	w := &watcher{dc: dc}
	w.removeUnmanaged(containers, "local")
	if want := []string{"/v1.44/containers/orphan"}; !reflect.DeepEqual(removed, want) {
		t.Fatalf("removed %v, want only %v; dependency lifecycle belongs to the orchestrator", removed, want)
	}
}

func TestManagedDependencyIdentification(t *testing.T) {
	for _, service := range []string{"metadata", "metadata/dns", "dns"} {
		if !managedDependency(metadata.Container{StackName: "network-services", ServiceName: service}) {
			t.Errorf("did not protect dependency %s", service)
		}
	}
	if managedDependency(metadata.Container{StackName: "application", ServiceName: "metadata"}) {
		t.Fatal("unrelated application unexpectedly treated as a platform dependency")
	}
}
