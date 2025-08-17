package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeClarityCE/plugin-php-sbom/src/project_finder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: These functions test the internal framework detection logic indirectly
// through the public FindPHPProjects function since the individual functions
// are not exported (they start with lowercase letters)

func TestFindPHPProjects(t *testing.T) {
	// Create temporary directory structure for testing
	tempDir, err := os.MkdirTemp("", "php-project-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test composer.json
	composerJSON := `{
		"name": "test/project",
		"type": "project",
		"description": "Test PHP project",
		"license": "MIT",
		"require": {
			"php": ">=8.1",
			"laravel/framework": "^10.0"
		},
		"require-dev": {
			"phpunit/phpunit": "^10.0"
		}
	}`

	composerJSONPath := filepath.Join(tempDir, "composer.json")
	err = os.WriteFile(composerJSONPath, []byte(composerJSON), 0644)
	require.NoError(t, err)

	// Create a test composer.lock
	composerLock := `{
		"_readme": ["test lock file"],
		"content-hash": "test-hash",
		"packages": [],
		"packages-dev": [],
		"aliases": [],
		"minimum-stability": "stable",
		"prefer-stable": true,
		"platform": {"php": ">=8.1"}
	}`

	composerLockPath := filepath.Join(tempDir, "composer.lock")
	err = os.WriteFile(composerLockPath, []byte(composerLock), 0644)
	require.NoError(t, err)

	// Test finding PHP projects
	projectInfo, err := project_finder.FindPHPProjects(tempDir)
	require.NoError(t, err)
	require.NotNil(t, projectInfo)

	// Verify project info
	assert.Equal(t, "test/project", projectInfo.Name)
	assert.Equal(t, "Test PHP project", projectInfo.Description)
	assert.Equal(t, "Laravel", projectInfo.Framework)
	assert.NotNil(t, projectInfo.ComposerJSON)
	assert.NotNil(t, projectInfo.ComposerLock)
	assert.False(t, projectInfo.IsMonorepo)

	// Verify composer.json was parsed correctly
	assert.Equal(t, "test/project", projectInfo.ComposerJSON.Name)
	assert.Equal(t, "project", projectInfo.ComposerJSON.Type)
	assert.Equal(t, ">=8.1", projectInfo.ComposerJSON.Require["php"])
}

func TestFindPHPProjectsNoComposerFile(t *testing.T) {
	// Create empty temporary directory
	tempDir, err := os.MkdirTemp("", "no-composer-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test finding PHP projects in directory without composer.json
	projectInfo, err := project_finder.FindPHPProjects(tempDir)
	assert.Error(t, err)
	assert.Nil(t, projectInfo)
	assert.Contains(t, err.Error(), "no composer.json files found")
}

func TestFindPHPProjectsInvalidComposerJSON(t *testing.T) {
	// Create temporary directory with invalid composer.json
	tempDir, err := os.MkdirTemp("", "invalid-composer-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create invalid composer.json
	invalidJSON := `{"name": "test", "invalid": json}`
	composerJSONPath := filepath.Join(tempDir, "composer.json")
	err = os.WriteFile(composerJSONPath, []byte(invalidJSON), 0644)
	require.NoError(t, err)

	// Test finding PHP projects
	projectInfo, err := project_finder.FindPHPProjects(tempDir)
	assert.Error(t, err)
	assert.Nil(t, projectInfo)
	assert.Contains(t, err.Error(), "failed to parse root composer.json")
}

func TestFindPHPProjectsMonorepo(t *testing.T) {
	// Create temporary directory structure for monorepo testing
	tempDir, err := os.MkdirTemp("", "monorepo-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create root composer.json
	rootComposer := `{
		"name": "company/monorepo",
		"type": "project",
		"description": "Monorepo with multiple packages"
	}`
	err = os.WriteFile(filepath.Join(tempDir, "composer.json"), []byte(rootComposer), 0644)
	require.NoError(t, err)

	// Create package1 directory and composer.json
	package1Dir := filepath.Join(tempDir, "packages", "package1")
	err = os.MkdirAll(package1Dir, 0755)
	require.NoError(t, err)

	package1Composer := `{
		"name": "company/package1",
		"type": "library",
		"description": "First package",
		"require": {
			"php": ">=8.0"
		}
	}`
	err = os.WriteFile(filepath.Join(package1Dir, "composer.json"), []byte(package1Composer), 0644)
	require.NoError(t, err)

	// Create package2 directory and composer.json
	package2Dir := filepath.Join(tempDir, "packages", "package2")
	err = os.MkdirAll(package2Dir, 0755)
	require.NoError(t, err)

	package2Composer := `{
		"name": "company/package2",
		"type": "library",
		"description": "Second package",
		"require": {
			"php": ">=8.1",
			"symfony/console": "^6.0"
		}
	}`
	err = os.WriteFile(filepath.Join(package2Dir, "composer.json"), []byte(package2Composer), 0644)
	require.NoError(t, err)

	// Test finding PHP projects
	projectInfo, err := project_finder.FindPHPProjects(tempDir)
	require.NoError(t, err)
	require.NotNil(t, projectInfo)

	// Verify main project info
	assert.Equal(t, "company/monorepo", projectInfo.Name)
	assert.True(t, projectInfo.IsMonorepo)

	// Verify root composer.json was parsed correctly
	assert.Equal(t, "company/monorepo", projectInfo.ComposerJSON.Name)
	assert.Equal(t, "project", projectInfo.ComposerJSON.Type)

	// Verify workspaces
	assert.Len(t, projectInfo.Workspaces, 2)

	// Find and verify package1
	var package1, package2 *project_finder.WorkspaceInfo
	for i := range projectInfo.Workspaces {
		ws := &projectInfo.Workspaces[i]
		if ws.ComposerJSON.Name == "company/package1" {
			package1 = ws
		} else if ws.ComposerJSON.Name == "company/package2" {
			package2 = ws
		}
	}

	require.NotNil(t, package1)
	assert.Equal(t, "company/package1", package1.ComposerJSON.Name)
	assert.Equal(t, "library", package1.ComposerJSON.Type)
	assert.Equal(t, "First package", package1.ComposerJSON.Description)

	require.NotNil(t, package2)
	assert.Equal(t, "company/package2", package2.ComposerJSON.Name)
	assert.Equal(t, "library", package2.ComposerJSON.Type)
	assert.Equal(t, "Second package", package2.ComposerJSON.Description)
	assert.Equal(t, ">=8.1", package2.ComposerJSON.Require["php"])
	assert.Equal(t, "^6.0", package2.ComposerJSON.Require["symfony/console"])
}

func TestFindPHPProjectsFrameworkDetection(t *testing.T) {
	tests := []struct {
		name              string
		composerJSON      string
		expectedFramework string
	}{
		{
			name: "Laravel project",
			composerJSON: `{
				"name": "laravel/test-app",
				"require": {
					"laravel/framework": "^10.0"
				}
			}`,
			expectedFramework: "Laravel",
		},
		{
			name: "Symfony project",
			composerJSON: `{
				"name": "symfony/test-app",
				"require": {
					"symfony/framework-bundle": "^6.0"
				}
			}`,
			expectedFramework: "Symfony",
		},
		{
			name: "CakePHP project",
			composerJSON: `{
				"name": "cakephp/test-app",
				"require": {
					"cakephp/cakephp": "^4.0"
				}
			}`,
			expectedFramework: "CakePHP",
		},
		{
			name: "Generic PHP project",
			composerJSON: `{
				"name": "example/library",
				"require": {
					"psr/log": "^3.0"
				}
			}`,
			expectedFramework: "Generic PHP",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create temporary directory
			tempDir, err := os.MkdirTemp("", "framework-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			// Create composer.json
			composerJSONPath := filepath.Join(tempDir, "composer.json")
			err = os.WriteFile(composerJSONPath, []byte(test.composerJSON), 0644)
			require.NoError(t, err)

			// Test framework detection
			projectInfo, err := project_finder.FindPHPProjects(tempDir)
			require.NoError(t, err)
			require.NotNil(t, projectInfo)

			assert.Equal(t, test.expectedFramework, projectInfo.Framework)
		})
	}
}

func TestFindPHPProjectsVendorDetection(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "vendor-detection-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create composer.json
	composerJSON := `{"name": "test/project"}`
	composerJSONPath := filepath.Join(tempDir, "composer.json")
	err = os.WriteFile(composerJSONPath, []byte(composerJSON), 0644)
	require.NoError(t, err)

	// Test without vendor directory
	projectInfo, err := project_finder.FindPHPProjects(tempDir)
	require.NoError(t, err)
	assert.False(t, projectInfo.HasVendorDirectory)

	// Create vendor directory
	vendorDir := filepath.Join(tempDir, "vendor")
	err = os.MkdirAll(vendorDir, 0755)
	require.NoError(t, err)

	// Test with vendor directory
	projectInfo, err = project_finder.FindPHPProjects(tempDir)
	require.NoError(t, err)
	assert.True(t, projectInfo.HasVendorDirectory)
}
