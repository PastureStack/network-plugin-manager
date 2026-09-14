package binexec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShellQuoteKeepsMetadataInsideOneLiteral(t *testing.T) {
	input := "service'$(touch /tmp/should-not-run)"
	want := "'service'\"'\"'$(touch /tmp/should-not-run)'"
	if got := shellQuote(input); got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

func TestNumericVersionComparison(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
		ok          bool
	}{
		{"0.14.37", "0.14.34", 1, true},
		{"v0.14.34", "0.14.37", -1, true},
		{"0.14.37", "0.14.37.0", 0, true},
		{"dev", "0.14.37", 0, false},
	}
	for _, test := range tests {
		got, ok := compareNumericVersions(test.left, test.right)
		if got != test.want || ok != test.ok {
			t.Fatalf("compareNumericVersions(%q, %q) = %d, %v", test.left, test.right, got, ok)
		}
	}
}

func TestProviderPreferenceKeepsNumericVersionsAheadOfDevelopmentLabels(t *testing.T) {
	tests := []struct {
		name                          string
		currentID, currentVersion     string
		candidateID, candidateVersion string
		want                          bool
	}{
		{"newer numeric version", "bbbb", "0.14.34", "cccc", "0.14.37", true},
		{"older numeric version", "bbbb", "0.14.37", "aaaa", "0.14.34", false},
		{"numeric replaces development label", "bbbb", "dev", "cccc", "0.14.37", true},
		{"development label cannot replace numeric", "bbbb", "0.14.37", "aaaa", "dev", false},
		{"equal version uses lower immutable id", "bbbb", "0.14.37", "aaaa", "0.14.37", true},
		{"equal version retains lower immutable id", "aaaa", "0.14.37", "bbbb", "0.14.37", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := preferProvider(test.currentID, test.currentVersion, test.candidateID, test.candidateVersion)
			if got != test.want {
				t.Fatalf("preferProvider(%q, %q, %q, %q) = %v, want %v", test.currentID, test.currentVersion, test.candidateID, test.candidateVersion, got, test.want)
			}
		})
	}
}

func TestBinaryNameValidation(t *testing.T) {
	for _, valid := range []string{"pasture-bridge", "driver_1.2"} {
		if !validBinaryName(valid) {
			t.Fatalf("valid binary name rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", ".", "..", "../driver", `dir\\driver`, "driver name", "$(id)"} {
		if validBinaryName(invalid) {
			t.Fatalf("invalid binary name accepted: %q", invalid)
		}
	}
}

func TestDriverWrapperUsesSelectedContainersPrivateBundle(t *testing.T) {
	wrapper := string(renderDriverWrapper("0123456789abcdef", "pasture-bridge"))
	for _, required := range []string{
		"containers/${target}/json",
		"private_binary=\"/opt/cni/bin/${binary_name}\"",
		"CNI_PATH=/opt/cni/bin",
		"\"${private_binary}\" \"$@\"",
		"-- \"$0\" \"$@\"",
	} {
		if !strings.Contains(wrapper, required) {
			t.Fatalf("driver wrapper is missing %q:\n%s", required, wrapper)
		}
	}
	for _, forbidden := range []string{"/containers/json", "service_label", "filters="} {
		if strings.Contains(wrapper, forbidden) {
			t.Fatalf("driver wrapper can reselect an unverified provider through %q:\n%s", forbidden, wrapper)
		}
	}
}

func TestWrapperFileMatchesDetectsOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pasture-bridge")
	expected := renderDriverWrapper("0123456789abcdef", "pasture-bridge")
	if err := os.WriteFile(path, expected, 0700); err != nil {
		t.Fatal(err)
	}
	if !wrapperFileMatches(path, expected) {
		t.Fatal("matching wrapper was reported as drifted")
	}
	if err := os.WriteFile(path, []byte("stale wrapper\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if wrapperFileMatches(path, expected) {
		t.Fatal("overwritten wrapper was reported as current")
	}
	if err := os.WriteFile(path, expected, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if wrapperFileMatches(path, expected) {
		t.Fatal("wrapper with non-executable permissions was reported as current")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "wrapper-target")
	if err := os.WriteFile(target, expected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if wrapperFileMatches(path, expected) {
		t.Fatal("symlinked wrapper was reported as a regular managed file")
	}
}

func TestAtomicWrapperWriteDoesNotFollowPredictableTemporarySymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "pasture-bridge")
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\nexit 0\n")
	if err := writeWrapperAtomic(path, content); err != nil {
		t.Fatal(err)
	}
	gotVictim, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotVictim) != "unchanged" {
		t.Fatalf("predictable temporary symlink target was overwritten: %q", gotVictim)
	}
	gotWrapper, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotWrapper) != string(content) {
		t.Fatalf("installed wrapper = %q, want %q", gotWrapper, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("installed wrapper permissions = %o, want 700", info.Mode().Perm())
	}
}
