package src

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeClarityCE/plugin-php-sbom/src/performance"
	"github.com/CodeClarityCE/plugin-php-sbom/src/project_finder"
)

// Lock fixtures are cut to this many packages per list, since big seeds stall the fuzzer.
const seedPackages = 3

// smallLock returns a composer.lock fixture as compact JSON with only its first few packages.
func smallLock(f *testing.F, data []byte) []byte {
	lock := map[string]any{}
	if err := json.Unmarshal(data, &lock); err != nil {
		f.Fatal(err)
	}
	for _, key := range []string{"packages", "packages-dev"} {
		if packages, ok := lock[key].([]any); ok {
			lock[key] = packages[:min(seedPackages, len(packages))]
		}
	}
	small, err := json.Marshal(lock)
	if err != nil {
		f.Fatal(err)
	}
	return small
}

// FuzzParseComposerProject checks that reading any composer.json and composer.lock pair,
// then building its workspaces, never panics. Start itself needs a broker, so it is not called.
func FuzzParseComposerProject(f *testing.F) {
	manifests, err := filepath.Glob(filepath.Join("..", "tests", "*", "composer.json.fixture"))
	if err != nil {
		f.Fatal(err)
	}
	for _, manifest := range manifests {
		jsonData, err := os.ReadFile(manifest) //nolint:gosec // G304: seed paths come from the repo's own testdata
		if err != nil {
			f.Fatal(err)
		}
		lockData, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), "composer.lock.fixture"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(jsonData, smallLock(f, lockData))
	}

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, jsonData []byte, lockData []byte) {
		if err := os.WriteFile(filepath.Join(dir, "composer.json"), jsonData, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "composer.lock"), lockData, 0o600); err != nil {
			t.Fatal(err)
		}
		projectInfo, err := project_finder.FindPHPProjects(dir)
		if err != nil {
			return
		}
		buildOptimizedWorkspaces(projectInfo, performance.NewObjectPool())
	})
}
