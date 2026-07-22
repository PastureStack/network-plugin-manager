package metadata

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientReadsVersionAndHosts(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected Accept header %q", request.Header.Get("Accept"))
		}
		switch request.URL.Path {
		case "/2016-07-29/version":
			fmt.Fprint(response, `"revision-1"`)
		case "/2016-07-29/hosts":
			fmt.Fprint(response, `[{"uuid":"host-1","agent_ip":"192.0.2.10"}]`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := NewClientAndWait(server.URL + "/2016-07-29")
	if err != nil {
		t.Fatalf("NewClientAndWait returned an error: %v", err)
	}
	version, err := client.GetVersion()
	if err != nil || version != "revision-1" {
		t.Fatalf("GetVersion = %q, %v", version, err)
	}
	host, err := client.GetHost("host-1")
	if err != nil {
		t.Fatalf("GetHost returned an error: %v", err)
	}
	if host.AgentIP != "192.0.2.10" {
		t.Fatalf("AgentIP = %q", host.AgentIP)
	}
}

func TestClientRejectsUnsafeBaseURLs(t *testing.T) {
	t.Helper()
	for _, rawURL := range []string{
		"file:///tmp/metadata",
		"http://user:password@example.test/metadata",
		"http://example.test/metadata?token=value",
		"http://example.test/metadata#fragment",
	} {
		if _, err := NewClientWithIPAndWait(rawURL, ""); err == nil {
			t.Errorf("expected %q to be rejected", rawURL)
		}
	}
	if _, err := NewClientWithIPAndWait("http://example.test/metadata", "not-an-ip"); err == nil {
		t.Fatal("expected invalid forwarded address to be rejected")
	}
}

func TestClientBlocksCrossOriginRedirects(t *testing.T) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fmt.Fprint(response, `"unexpected"`)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	_, err := NewClient(origin.URL).GetVersion()
	if err == nil || !strings.Contains(err.Error(), "redirect changed origin") {
		t.Fatalf("unexpected redirect error: %v", err)
	}
}

func TestClientDoesNotExposeResponseBodiesInErrors(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(response, "sensitive-response-value")
	}))
	defer server.Close()

	_, err := NewClient(server.URL).GetVersion()
	if err == nil {
		t.Fatal("expected request to fail")
	}
	if strings.Contains(err.Error(), "sensitive-response-value") {
		t.Fatalf("response body leaked in error: %v", err)
	}
}

func TestClientRejectsTraversal(t *testing.T) {
	t.Helper()
	_, err := NewClient("http://example.test/metadata").SendRequest("/../secrets")
	if err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}

func TestOnChangeWithErrorPublishesAChangedVersion(t *testing.T) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if requests.Add(1) == 1 {
			fmt.Fprint(response, `"revision-2"`)
			return
		}
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	var received string
	err := NewClient(server.URL).OnChangeWithError(1, func(version string) {
		received = version
	})
	if err == nil {
		t.Fatal("expected the second version request to fail")
	}
	if received != "revision-2" {
		t.Fatalf("received version %q", received)
	}
}

func TestHTTPClientUsesRequestScopedResponseTimeouts(t *testing.T) {
	client, err := newHTTPClient("http://example.test/metadata", "")
	if err != nil {
		t.Fatalf("newHTTPClient returned an error: %v", err)
	}
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.client.Transport)
	}
	if transport.ResponseHeaderTimeout != 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want 0 so long polls use their request context", transport.ResponseHeaderTimeout)
	}
}
