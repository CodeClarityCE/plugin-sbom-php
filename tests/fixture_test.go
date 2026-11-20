package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureSuffix = ".fixture"

// useFixture copies tests/<name> into a tempdir under the same folder name,
// restores real manifest names and changes into that tempdir.
// It returns the path to pass to plugin.Start and the source folder for goldens.
func useFixture(t *testing.T, name string) (startPath string, sourceDir string) {
	t.Helper()
	sourceDir, err := filepath.Abs(name)
	if err != nil {
		t.Fatalf("resolve fixture %s: %v", name, err)
	}
	root := t.TempDir()
	err = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(root, name, strings.TrimSuffix(rel, fixtureSuffix))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return err
		}
		// Keep mtimes, which appear in the PHAR section of the SBOM.
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
	if err != nil {
		t.Fatalf("copy fixture %s: %v", name, err)
	}
	// Run from the tempdir with a relative path, so output paths match the goldens.
	t.Chdir(root)
	return "./" + name, sourceDir
}
