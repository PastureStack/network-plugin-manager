package glue

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/engine-api/types/container"
)

func TestNewCNIExecProvidesCurrentAndLegacyContainerUUIDArgs(t *testing.T) {
	originalDir := CniDir
	CniDir = filepath.Join(t.TempDir(), "%s.d")
	defer func() { CniDir = originalDir }()

	if err := os.MkdirAll(filepath.Join(filepath.Dir(CniDir), "ipsec.d"), 0700); err != nil {
		t.Fatalf("create CNI config directory: %v", err)
	}
	state := &DockerPluginState{
		ContainerID: "docker-container-id",
		Pid:         1234,
		HostConfig: container.HostConfig{
			NetworkMode: container.NetworkMode("ipsec"),
		},
		Config: container.Config{
			Labels: map[string]string{
				"io.rancher.container.uuid": "platform-container-uuid",
			},
		},
	}

	exec, err := NewCNIExec(state)
	if err != nil {
		t.Fatalf("NewCNIExec returned an error: %v", err)
	}
	args := map[string]string{}
	for _, arg := range exec.runtimeConf.Args {
		args[arg[0]] = arg[1]
	}
	for _, name := range []string{"RancherContainerUUID", "PlatformContainerUUID"} {
		if args[name] != "platform-container-uuid" {
			t.Fatalf("%s = %q, want platform-container-uuid", name, args[name])
		}
	}
}
