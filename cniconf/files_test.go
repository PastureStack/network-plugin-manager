package cniconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/containernetworking/cni/libcni"
	"github.com/moby/moby/client"
)

func migrationNetwork(legacy bool) metadata.Network {
	file, name, driver, ipam := currentConfigName, "pasturestack-cni-network", "pasture-bridge", "metadata-cni-ipam"
	if legacy {
		file, name, driver, ipam = legacyConfigName, "rancher-cni-network", "rancher-bridge", "rancher-cni-ipam"
	}
	return metadata.Network{
		Name: "ipsec", UUID: "network-ipsec",
		Metadata: map[string]interface{}{"cniConfig": map[string]interface{}{
			file: map[string]interface{}{
				"cniVersion": "0.3.1", "name": name, "type": driver,
				"bridge": "docker0", "bridgeSubnet": "10.42.0.0/16", "hostNat": true,
				"ipam": map[string]interface{}{"type": ipam},
			},
		}},
	}
}

func migrationFixture(t *testing.T) (*watcher, string, []byte) {
	t.Helper()
	previousDir := cniDir
	cniDir = filepath.Join(t.TempDir(), "%s.d")
	t.Cleanup(func() { cniDir = previousDir })
	directory := filepath.Join(filepath.Dir(cniDir), "ipsec.d")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := migrationNetwork(true).Metadata["cniConfig"].(map[string]interface{})[legacyConfigName]
	content, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(directory, legacyConfigName), content)
	return &watcher{applied: map[string]metadata.Network{}}, directory, content
}

func writeFixture(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path string, expected []byte) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, expected) {
		t.Fatalf("%s content = %q, error = %v; want %q", path, content, err, expected)
	}
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no %s, got %v", path, err)
	}
}

func TestPlatformConfigMigrationLeavesOneActiveConfigAndIsIdempotent(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	for i := 0; i < 2; i++ {
		if err := w.apply(migrationNetwork(false)); err != nil {
			t.Fatal(err)
		}
		files, err := libcni.ConfFiles(directory, []string{".conf", ".json"})
		if err != nil || len(files) != 1 || filepath.Base(files[0]) != currentConfigName {
			t.Fatalf("active configs = %v, error = %v", files, err)
		}
		assertFileContent(t, filepath.Join(directory, legacyConfigName+retiredSuffix), legacy)
		assertNoFile(t, filepath.Join(directory, legacyConfigName))
	}
	if _, ok := w.applied["ipsec"]; !ok || w.lastApplied.IsZero() {
		t.Fatal("successful migration was not recorded")
	}
	temporaries, err := filepath.Glob(filepath.Join(directory, ".*.tmp-*"))
	if err != nil || len(temporaries) != 0 {
		t.Fatalf("temporary config files remain: %v, %v", temporaries, err)
	}
}

func TestLegacyMetadataKeepsItsActiveConfig(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	if err := w.apply(migrationNetwork(true)); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
	assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
	assertNoFile(t, filepath.Join(directory, currentConfigName))
}

func TestPlatformConfigMigrationConvergesUpgradeRollbackAndUpgrade(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	for _, rollback := range []bool{false, true, false, true} {
		if err := w.apply(migrationNetwork(rollback)); err != nil {
			t.Fatal(err)
		}
		want := currentConfigName
		if rollback {
			want = legacyConfigName
		}
		files, err := libcni.ConfFiles(directory, []string{".conf", ".json"})
		if err != nil || len(files) != 1 || filepath.Base(files[0]) != want {
			t.Fatalf("rollback=%v: active configs = %v, error = %v, want only %s", rollback, files, err, want)
		}
		assertFileContent(t, filepath.Join(directory, legacyConfigName+retiredSuffix), legacy)
	}
}

func TestPlatformConfigMigrationNeverRetiresDesiredFiles(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	network := migrationNetwork(false)
	network.Metadata["cniConfig"].(map[string]interface{})[legacyConfigName] =
		migrationNetwork(true).Metadata["cniConfig"].(map[string]interface{})[legacyConfigName]
	if err := w.apply(network); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
	assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
	assertNoFile(t, filepath.Join(directory, currentConfigName+retiredSuffix))
}

func TestPlatformConfigMigrationPreservesForeignFiles(t *testing.T) {
	w, directory, _ := migrationFixture(t)
	foreign := []byte(`{"name":"administrator-network","type":"bridge","ipam":{"type":"host-local"}}`)
	writeFixture(t, filepath.Join(directory, legacyConfigName), foreign)
	admin := []byte(`{"name":"audit-network","type":"loopback"}`)
	writeFixture(t, filepath.Join(directory, "90-administrator.json"), admin)
	if err := w.apply(migrationNetwork(false)); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName), foreign)
	assertFileContent(t, filepath.Join(directory, "90-administrator.json"), admin)
	assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
}

func TestPlatformConfigMigrationRejectsUnclassifiableLegacyConfig(t *testing.T) {
	for _, content := range []string{
		`{`, `null`,
		`{"name":"rancher-cni-network","type":"bridge","ipam":{"type":"host-local"}}`,
		`{"name":"custom","type":"rancher-bridge","ipam":{"type":"rancher-cni-ipam"}}`,
	} {
		t.Run(content, func(t *testing.T) {
			w, directory, _ := migrationFixture(t)
			writeFixture(t, filepath.Join(directory, legacyConfigName), []byte(content))
			if err := w.apply(migrationNetwork(false)); err == nil {
				t.Fatal("unclassifiable legacy config was silently migrated")
			}
			assertFileContent(t, filepath.Join(directory, legacyConfigName), []byte(content))
			assertNoFile(t, filepath.Join(directory, currentConfigName))
			assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
		})
	}
}

func TestPlatformConfigMigrationRequiresExactSuccessorContract(t *testing.T) {
	for _, field := range []string{"name", "type", "ipam"} {
		t.Run(field, func(t *testing.T) {
			w, directory, legacy := migrationFixture(t)
			network := migrationNetwork(false)
			config := network.Metadata["cniConfig"].(map[string]interface{})[currentConfigName].(map[string]interface{})
			if field == "ipam" {
				config[field] = map[string]interface{}{"type": "host-local"}
			} else {
				config[field] = "custom"
			}
			if err := w.apply(network); err != nil {
				t.Fatal(err)
			}
			assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
			assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
		})
	}
}

func TestPlatformConfigMigrationHandlesExistingBackupWithoutOverwriting(t *testing.T) {
	for _, identical := range []bool{true, false} {
		t.Run(map[bool]string{true: "identical", false: "different"}[identical], func(t *testing.T) {
			w, directory, legacy := migrationFixture(t)
			backup := legacy
			if !identical {
				backup = []byte("previous retired configuration")
			}
			backupPath := filepath.Join(directory, legacyConfigName+retiredSuffix)
			writeFixture(t, backupPath, backup)
			err := w.apply(migrationNetwork(false))
			if identical && err != nil {
				t.Fatal(err)
			}
			if !identical && err == nil {
				t.Fatal("different backup was overwritten")
			}
			assertFileContent(t, backupPath, backup)
			if identical {
				assertNoFile(t, filepath.Join(directory, legacyConfigName))
			} else {
				assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
				assertNoFile(t, filepath.Join(directory, currentConfigName))
			}
		})
	}
}

func TestPlatformConfigMigrationDoesNotRetireAfterAnyWriteFails(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	network := migrationNetwork(false)
	network.Metadata["cniConfig"].(map[string]interface{})["90-extra.conf"] = map[string]interface{}{"type": "loopback"}
	writes := 0
	failure := errors.New("injected config write failure")
	err := w.applyWithWriter(network, func(path string, content []byte) error {
		writes++
		if writes == 2 {
			return failure
		}
		return writeConfigAtomic(path, content)
	})
	if !errors.Is(err, failure) || writes != 2 {
		t.Fatalf("apply error = %v, writes = %d", err, writes)
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
	assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
	if len(w.applied) != 0 || !w.lastApplied.IsZero() {
		t.Fatal("failed apply was recorded as successful")
	}
	if err := w.apply(network); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName+retiredSuffix), legacy)
}

func TestConfigPreflightValidatesEveryDesiredConfigBeforeWriting(t *testing.T) {
	for _, invalid := range []interface{}{make(chan int), map[string]interface{}{"name": "missing-type"}} {
		w, directory, legacy := migrationFixture(t)
		network := migrationNetwork(false)
		network.Metadata["cniConfig"].(map[string]interface{})["99-invalid.conf"] = invalid
		if err := w.apply(network); err == nil {
			t.Fatal("invalid desired config was accepted")
		}
		assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
		assertNoFile(t, filepath.Join(directory, currentConfigName))
	}
}

func TestConfigMigrationRejectsPathTraversal(t *testing.T) {
	for _, unsafe := range []string{"../outside", `..\outside`, "/absolute", "driver:stream", ".."} {
		t.Run(unsafe, func(t *testing.T) {
			w, directory, legacy := migrationFixture(t)
			network := migrationNetwork(false)
			network.Name = unsafe
			if err := w.apply(network); err == nil {
				t.Fatal("unsafe network path was accepted")
			}
			network = migrationNetwork(false)
			unsafeFile := unsafe
			if unsafe != ".." {
				unsafeFile += ".conf"
			}
			network.Metadata["cniConfig"].(map[string]interface{})[unsafeFile] = map[string]interface{}{"type": "loopback"}
			if err := w.apply(network); err == nil {
				t.Fatal("unsafe config path was accepted")
			}
			assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
			assertNoFile(t, filepath.Join(directory, currentConfigName))
		})
	}
}

func symlinkFixture(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
}

func TestConfigMigrationRejectsSymlinkedConfigAndBackup(t *testing.T) {
	for _, name := range []string{legacyConfigName, currentConfigName, legacyConfigName + retiredSuffix} {
		t.Run(name, func(t *testing.T) {
			w, directory, legacy := migrationFixture(t)
			victim := filepath.Join(t.TempDir(), "administrator-file")
			writeFixture(t, victim, legacy)
			path := filepath.Join(directory, name)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			symlinkFixture(t, victim, path)
			if err := w.apply(migrationNetwork(false)); err == nil {
				t.Fatal("symlinked CNI file was accepted")
			}
			assertFileContent(t, victim, legacy)
			if name != currentConfigName {
				assertNoFile(t, filepath.Join(directory, currentConfigName))
			}
		})
	}
}

func TestConfigMigrationRejectsSymlinkedDirectory(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	actual := directory + "-administrator"
	if err := os.Rename(directory, actual); err != nil {
		t.Fatal(err)
	}
	symlinkFixture(t, actual, directory)
	if err := w.apply(migrationNetwork(false)); err == nil {
		t.Fatal("symlinked network directory was accepted")
	}
	assertFileContent(t, filepath.Join(actual, legacyConfigName), legacy)
	assertNoFile(t, filepath.Join(actual, currentConfigName))
}

func TestLegacyRetirementRejectsChangesAfterPreflight(t *testing.T) {
	_, directory, _ := migrationFixture(t)
	files, err := prepareConfigFiles(directory, migrationNetwork(false).Metadata["cniConfig"].(map[string]interface{}))
	if err != nil {
		t.Fatal(err)
	}
	retirement, err := prepareLegacyRetirement(directory, files)
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte(`{"type":"administrator-plugin"}`)
	writeFixture(t, filepath.Join(directory, legacyConfigName), changed)
	if err := retirement.retire(); err == nil {
		t.Fatal("concurrently changed legacy config was retired")
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName), changed)
	assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
}

func TestManagedSymlinkFailurePreservesPreviousPointer(t *testing.T) {
	for _, stage := range []string{"create", "rename"} {
		t.Run(stage, func(t *testing.T) {
			directory := t.TempDir()
			oldDirectory := filepath.Join(directory, "old.d")
			if err := os.Mkdir(oldDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			oldConfig := []byte(`{"type":"administrator-plugin"}`)
			writeFixture(t, filepath.Join(oldDirectory, "10-old.conf"), oldConfig)
			path := filepath.Join(directory, "managed.d")
			symlinkFixture(t, "old.d", path)
			failure := errors.New("injected symlink failure")
			symlink, rename := os.Symlink, os.Rename
			if stage == "create" {
				symlink = func(string, string) error { return failure }
			} else {
				rename = func(string, string) error { return failure }
			}
			if err := replaceManagedSymlinkWithOps(path, "new.d", symlink, rename); !errors.Is(err, failure) {
				t.Fatalf("replace error = %v", err)
			}
			assertFileContent(t, filepath.Join(path, "10-old.conf"), oldConfig)
			if target, err := os.Readlink(path); err != nil || target != "old.d" {
				t.Fatalf("old pointer changed: %q, %v", target, err)
			}
			staged, err := filepath.Glob(filepath.Join(directory, ".managed.d.tmp-*"))
			if err != nil || len(staged) != 0 {
				t.Fatalf("staged pointers remain: %v, %v", staged, err)
			}
		})
	}
}

func TestManagedSymlinkRejectsAdministratorDirectory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "managed.d")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	admin := []byte(`{"type":"administrator-plugin"}`)
	writeFixture(t, filepath.Join(path, "90-admin.conf"), admin)
	if err := replaceManagedSymlink(path, "new.d"); err == nil {
		t.Fatal("administrator directory was replaced")
	}
	assertFileContent(t, filepath.Join(path, "90-admin.conf"), admin)
}

func TestManagedSymlinkReplacementAndUnchangedDefaultPointer(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	path := filepath.Join(filepath.Dir(directory), "managed.d")
	symlinkFixture(t, "previous.d", path)
	network := migrationNetwork(false)
	network.Default = true
	var previous os.FileInfo
	for i := 0; i < 2; i++ {
		if err := w.apply(network); err != nil {
			t.Fatal(err)
		}
		if target, err := os.Readlink(path); err != nil || target != "ipsec.d" {
			t.Fatalf("managed pointer = %q, %v", target, err)
		}
		assertFileContent(t, filepath.Join(directory, legacyConfigName+retiredSuffix), legacy)
		pointer, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !os.SameFile(previous, pointer) {
			t.Fatal("already correct managed pointer was unnecessarily replaced")
		}
		previous = pointer
	}
}

func TestConfigMigrationPreservesOldConfigIfDefaultPointerFails(t *testing.T) {
	w, directory, legacy := migrationFixture(t)
	if err := os.Mkdir(filepath.Join(filepath.Dir(directory), "managed.d"), 0700); err != nil {
		t.Fatal(err)
	}
	network := migrationNetwork(false)
	network.Default = true
	if err := w.apply(network); err == nil {
		t.Fatal("invalid managed pointer was accepted")
	}
	assertFileContent(t, filepath.Join(directory, legacyConfigName), legacy)
	assertNoFile(t, filepath.Join(directory, legacyConfigName+retiredSuffix))
}

type configMetadata struct {
	metadata.Client
	network metadata.Network
}

func (m configMetadata) GetNetworks() ([]metadata.Network, error) {
	return []metadata.Network{m.network}, nil
}
func (m configMetadata) GetSelfHost() (metadata.Host, error) {
	return metadata.Host{UUID: "local-host"}, nil
}
func (m configMetadata) GetServices() ([]metadata.Service, error) {
	return []metadata.Service{{Kind: "networkDriverService", Containers: []metadata.Container{{HostUUID: "local-host"}}}}, nil
}

func TestOnChangeReturnsConfigMigrationFailure(t *testing.T) {
	w, directory, _ := migrationFixture(t)
	writeFixture(t, filepath.Join(directory, legacyConfigName), []byte("invalid JSON"))
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	docker, err := client.New(client.WithHost("tcp://"+server.Listener.Addr().String()), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	w.c = configMetadata{network: migrationNetwork(false)}
	w.dc = docker
	if err := w.onChange(""); err == nil || !strings.Contains(err.Error(), "cannot classify legacy CNI config") {
		t.Fatalf("migration error was swallowed: %v", err)
	}
}
