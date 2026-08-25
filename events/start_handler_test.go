package events

import (
	"reflect"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestGetDNSSearchUsesPastureDomain(t *testing.T) {
	container := &container.InspectResponse{
		Config: &container.Config{Labels: map[string]string{
			"io.rancher.stack_service.name": "application/service",
		}},
		HostConfig: &container.HostConfig{DNSSearch: []string{"example.test"}},
	}

	actual := getDNSSearch(container)
	expected := []string{
		"service.application.pasture.internal",
		"application.pasture.internal",
		"example.test",
		"pasture.internal",
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("search domains = %#v, want %#v", actual, expected)
	}
}

func TestGetDNSSearchIgnoresMalformedServiceLabel(t *testing.T) {
	container := &container.InspectResponse{
		Config: &container.Config{Labels: map[string]string{
			"io.rancher.stack_service.name": "missing-separator",
		}},
		HostConfig: &container.HostConfig{},
	}

	actual := getDNSSearch(container)
	if !reflect.DeepEqual(actual, []string{"pasture.internal"}) {
		t.Fatalf("search domains = %#v", actual)
	}
}
