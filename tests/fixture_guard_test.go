package main

import (
	"io/fs"
	"path/filepath"
	"testing"
)

// Manifest and lockfile names that GitHub scans for dependency alerts.
var realManifestNames = map[string]bool{
	"composer.json":     true,
	"composer.lock":     true,
	"package.json":      true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
}

// TestFixturesStoreManifestsRenamed fails on any real-named manifest in a test project.
func TestFixturesStoreManifestsRenamed(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && realManifestNames[d.Name()] {
			t.Errorf("tests/%s has a real manifest name; store it as tests/%s.fixture", path, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk test fixtures: %v", err)
	}
}
