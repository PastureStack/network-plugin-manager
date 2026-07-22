package metadata

import (
	"os"
	"testing"
)

func TestLiveMetadataContract(t *testing.T) {
	rawURL := os.Getenv("PLATFORM_METADATA_TEST_URL")
	if rawURL == "" {
		t.Skip("PLATFORM_METADATA_TEST_URL is not set")
	}

	client, err := NewClientAndWait(rawURL)
	if err != nil {
		t.Fatalf("metadata connection failed: %v", err)
	}
	version, err := client.GetVersion()
	if err != nil || version == "" {
		t.Fatalf("metadata version contract failed: %v", err)
	}
	host, err := client.GetSelfHost()
	if err != nil || host.UUID == "" {
		t.Fatalf("self host contract failed: %v", err)
	}
	if _, err := client.GetHosts(); err != nil {
		t.Fatalf("hosts contract failed: %v", err)
	}
	if _, err := client.GetContainers(); err != nil {
		t.Fatalf("containers contract failed: %v", err)
	}
	if _, err := client.GetServices(); err != nil {
		t.Fatalf("services contract failed: %v", err)
	}
	if _, err := client.GetNetworks(); err != nil {
		t.Fatalf("networks contract failed: %v", err)
	}
}
