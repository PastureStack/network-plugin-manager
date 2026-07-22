package events

import (
	"reflect"
	"testing"

	docker "github.com/fsouza/go-dockerclient"
)

func TestGetDNSSearchUsesPastureDomain(t *testing.T) {
	container := &docker.Container{
		Config: &docker.Config{Labels: map[string]string{
			"io.rancher.stack_service.name": "application/service",
		}},
		HostConfig: &docker.HostConfig{DNSSearch: []string{"example.test"}},
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
	container := &docker.Container{
		Config: &docker.Config{Labels: map[string]string{
			"io.rancher.stack_service.name": "missing-separator",
		}},
		HostConfig: &docker.HostConfig{},
	}

	actual := getDNSSearch(container)
	if !reflect.DeepEqual(actual, []string{"pasture.internal"}) {
		t.Fatalf("search domains = %#v", actual)
	}
}
