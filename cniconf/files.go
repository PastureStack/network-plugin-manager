package cniconf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/containernetworking/cni/libcni"
)

const (
	legacyConfigName  = "10-rancher.conf"
	currentConfigName = "10-pasturestack.conf"
	retiredSuffix     = ".pasturestack-retired"
)

type configFile struct {
	path    string
	content []byte
}

// Metadata filenames and technical network names are single path components.
// The allowed characters match CNI's network-name character set; UI display
// names are not used as paths here.
func validConfigName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func checkConfigDirectory(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return fmt.Errorf("CNI directory is not a regular directory: %s", current)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func ensureConfigDirectory(path string) error {
	if err := checkConfigDirectory(path); err != nil {
		return err
	}
	return os.MkdirAll(path, 0700)
}

func checkConfigFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("CNI file is not a regular file: %s", path)
	}
	return nil
}

// Validate and serialize every desired file before changing any active config.
func prepareConfigFiles(directory string, configs map[string]interface{}) ([]configFile, error) {
	if err := checkConfigDirectory(directory); err != nil {
		return nil, err
	}
	files := make([]configFile, 0, len(configs))
	for name, config := range configs {
		if !validConfigName(name) {
			return nil, fmt.Errorf("invalid CNI config filename %q", name)
		}
		path := filepath.Join(directory, name)
		if err := checkConfigFile(path); err != nil {
			return nil, err
		}
		content, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode CNI config %q: %w", name, err)
		}
		if _, err := libcni.NetworkPluginConfFromBytes(content); err != nil {
			return nil, fmt.Errorf("validate CNI config %q: %w", name, err)
		}
		files = append(files, configFile{path: path, content: content})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

func writeConfigAtomic(path string, content []byte) (err error) {
	if err := checkConfigFile(path); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create CNI config temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write CNI config temporary file: %w", err)
	}
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := checkConfigFile(path); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install CNI config: %w", err)
	}
	return nil
}

type bridgeContract struct {
	Name string `json:"name"`
	Type string `json:"type"`
	IPAM struct {
		Type string `json:"type"`
	} `json:"ipam"`
}

type legacyRetirement struct {
	path    string
	backup  string
	content []byte
}

// Only the known platform IPsec filename transition is reconciled, in either
// upgrade or rollback direction. Other files have no provable ownership.
func prepareLegacyRetirement(directory string, files []configFile) (*legacyRetirement, error) {
	var current, legacy *configFile
	for i := range files {
		switch filepath.Base(files[i].path) {
		case legacyConfigName:
			legacy = &files[i]
		case currentConfigName:
			current = &files[i]
		}
	}
	if (current == nil && legacy == nil) || (current != nil && legacy != nil) {
		// Never retire a config still explicitly requested by Metadata.
		return nil, nil
	}
	currentContract := [3]string{"pasturestack-cni-network", "pasture-bridge", "metadata-cni-ipam"}
	legacyContract := [3]string{"rancher-cni-network", "rancher-bridge", "rancher-cni-ipam"}
	successor, expected, oldName, oldExpected := current, currentContract, legacyConfigName, legacyContract
	if legacy != nil {
		successor, expected, oldName, oldExpected = legacy, legacyContract, currentConfigName, currentContract
	}
	var desired bridgeContract
	if err := json.Unmarshal(successor.content, &desired); err != nil || matchingContractFields(desired, expected) != 3 {
		return nil, nil
	}
	path := filepath.Join(directory, oldName)
	if err := checkConfigFile(path); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var old bridgeContract
	if _, err := libcni.NetworkPluginConfFromBytes(content); err != nil {
		return nil, fmt.Errorf("cannot classify legacy CNI config %s: %w", path, err)
	}
	if err := json.Unmarshal(content, &old); err != nil {
		return nil, fmt.Errorf("cannot classify legacy CNI config %s: %w", path, err)
	}
	ownedFields := matchingContractFields(old, oldExpected)
	if ownedFields == 0 {
		return nil, nil
	}
	if ownedFields != 3 {
		return nil, fmt.Errorf("ambiguous platform ownership of legacy CNI config %s", path)
	}
	retirement := &legacyRetirement{path: path, backup: path + retiredSuffix, content: content}
	if err := retirement.checkBackup(); err != nil {
		return nil, err
	}
	return retirement, nil
}

func matchingContractFields(config bridgeContract, expected [3]string) int {
	matched := 0
	for i, actual := range [3]string{config.Name, config.Type, config.IPAM.Type} {
		if actual == expected[i] {
			matched++
		}
	}
	return matched
}

func (r *legacyRetirement) checkBackup() error {
	if err := checkConfigFile(r.backup); err != nil {
		return err
	}
	backup, err := os.ReadFile(r.backup)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(backup, r.content) {
		return fmt.Errorf("retired CNI backup differs from active legacy config: %s", r.backup)
	}
	return nil
}

func (r *legacyRetirement) retire() error {
	if r == nil {
		return nil
	}
	if err := checkConfigFile(r.path); err != nil {
		return err
	}
	content, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, r.content) {
		return fmt.Errorf("legacy CNI config changed during migration: %s", r.path)
	}
	if err := r.checkBackup(); err != nil {
		return err
	}
	if _, err := os.Lstat(r.backup); err == nil {
		// An identical recoverable copy already exists; never overwrite it.
		return os.Remove(r.path)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(r.path, r.backup)
}

// Stage the new link before replacing an existing pointer, so a failure cannot
// remove the previously working managed network link.
func replaceManagedSymlink(path, target string) error {
	return replaceManagedSymlinkWithOps(path, target, os.Symlink, os.Rename)
}

func replaceManagedSymlinkWithOps(path, target string, symlink, rename func(string, string) error) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("managed CNI path is not a symlink: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(path), ".managed.d.tmp-*")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	if err := staged.Close(); err != nil {
		_ = os.Remove(stagedPath)
		return err
	}
	defer os.Remove(stagedPath)
	if err := os.Remove(stagedPath); err != nil {
		return err
	}
	if err := symlink(target, stagedPath); err != nil {
		return err
	}
	return rename(stagedPath, path)
}
