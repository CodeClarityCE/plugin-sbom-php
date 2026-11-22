package main

import (
	"path/filepath"
	"testing"

	plugin "github.com/CodeClarityCE/plugin-php-sbom/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreatePassbolt(t *testing.T) {
	dir, src := useFixture(t, "test1")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test PHP-specific fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.Equal(t, "passbolt/passbolt_api", out.AnalysisInfo.ProjectName)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")
	assert.NotEmpty(t, defaultWs.Dependencies, "Should have dependencies")
	assert.NotEmpty(t, defaultWs.Start.Dependencies, "Should have direct dependencies")

	// Test specific dependencies we know exist in Passbolt
	_, hasCakePHP := defaultWs.Dependencies["cakephp/cakephp"]
	assert.True(t, hasCakePHP, "Should have CakePHP dependency")

	_, hasRamseyUuid := defaultWs.Dependencies["ramsey/uuid"]
	assert.True(t, hasRamseyUuid, "Should have ramsey/uuid dependency")

	// Test framework detection
	assert.Contains(t, []string{"CakePHP", "Generic PHP"}, out.AnalysisInfo.Extra.Framework)

	// Test that dev dependencies are separate
	devDepsCount := len(defaultWs.Start.DevDependencies)
	assert.Greater(t, devDepsCount, 0, "Should have dev dependencies")

	// Test license detection
	foundLicenses := false
	for _, versions := range defaultWs.Dependencies {
		for _, version := range versions {
			if len(version.Licenses) > 0 {
				foundLicenses = true
				break
			}
		}
		if foundLicenses {
			break
		}
	}
	assert.True(t, foundLicenses, "Should detect licenses in dependencies")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreateTest1EdgeCases(t *testing.T) {
	dir, _ := useFixture(t, "test1")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Test edge cases and detailed structure
	assert.NotNil(t, out)

	// Test paths are set correctly
	assert.Contains(t, out.AnalysisInfo.Paths.PackageFile, "composer.json")
	assert.Contains(t, out.AnalysisInfo.Paths.Lockfile, "composer.lock")

	// Test timing information is present
	assert.NotEmpty(t, out.AnalysisInfo.Time.AnalysisStartTime)
	assert.NotEmpty(t, out.AnalysisInfo.Time.AnalysisEndTime)
	assert.Greater(t, out.AnalysisInfo.Time.AnalysisDeltaTime, float64(0))

	// Test workspaces info
	assert.Equal(t, ".", out.AnalysisInfo.Workspaces.DefaultWorkspaceName)
	assert.Equal(t, "self-managed", out.AnalysisInfo.Workspaces.SelfManagedWorkspaceName)

	// Test version separators (compatible with js-sbom)
	assert.Equal(t, "@", out.AnalysisInfo.Extra.VersionSeperator)
	assert.Equal(t, "/", out.AnalysisInfo.Extra.ImportPathSeperator)

	// Test dependency structure matches js-sbom format
	defaultWs := out.WorkSpaces["."]
	for depName, versions := range defaultWs.Dependencies {
		assert.NotEmpty(t, depName, "Dependency name should not be empty")
		assert.NotEmpty(t, versions, "Dependency versions should not be empty")

		for versionStr, versionInfo := range versions {
			assert.NotEmpty(t, versionStr, "Version string should not be empty")
			assert.Contains(t, versionInfo.Key, "@", "Version key should contain @ separator")

			// Test boolean fields are set
			assert.True(t, versionInfo.Dev || versionInfo.Prod, "Should be either dev or prod dependency")
			assert.True(t, versionInfo.Direct || versionInfo.Transitive, "Should be either direct or transitive")
		}
	}
}

func TestErrorHandling(t *testing.T) {
	// Test with non-existent directory
	out := plugin.Start("./nonexistent", uuid.UUID{}, nil)

	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.FAILURE, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.AnalysisInfo.Errors)
}

func TestCreateLaravel(t *testing.T) {
	dir, src := useFixture(t, "test2-laravel")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test Laravel-specific fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.Equal(t, "laravel/laravel", out.AnalysisInfo.ProjectName)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Test framework detection should identify Laravel
	assert.Contains(t, []string{"Laravel", "Generic PHP"}, out.AnalysisInfo.Extra.Framework)

	assert.NotEmpty(t, defaultWs.Dependencies, "Should parse dependencies from composer.lock")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreateSymfony(t *testing.T) {
	dir, src := useFixture(t, "test3-symfony")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test Symfony-specific fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Test framework detection should identify Symfony
	assert.Equal(t, "Symfony", out.AnalysisInfo.Extra.Framework)

	assert.NotEmpty(t, defaultWs.Dependencies, "Should parse dependencies from composer.lock")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreateWordPress(t *testing.T) {
	dir, src := useFixture(t, "test4-wordpress")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test WordPress-specific fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.Equal(t, "wordpress/wordpress-site", out.AnalysisInfo.ProjectName)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Test framework detection should identify WordPress or Generic PHP
	assert.Contains(t, []string{"WordPress", "Generic PHP"}, out.AnalysisInfo.Extra.Framework)

	assert.NotEmpty(t, defaultWs.Dependencies, "Should parse dependencies from composer.lock")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreateCodeIgniter(t *testing.T) {
	dir, src := useFixture(t, "test5-codeigniter")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test CodeIgniter-specific fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.Equal(t, "codeigniter4/codeigniter-app", out.AnalysisInfo.ProjectName)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Test framework detection - actual output is "CodeIgniter 4"
	assert.Equal(t, "CodeIgniter 4", out.AnalysisInfo.Extra.Framework)

	assert.NotEmpty(t, defaultWs.Dependencies, "Should parse dependencies from composer.lock")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreatePurePHP(t *testing.T) {
	dir, src := useFixture(t, "test6-pure-php")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test pure PHP library fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.Equal(t, "example/pure-php-project", out.AnalysisInfo.ProjectName)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Test framework detection - actual output is "Symfony Components" due to Symfony dependencies
	assert.Equal(t, "Symfony Components", out.AnalysisInfo.Extra.Framework)

	assert.NotEmpty(t, defaultWs.Dependencies, "Should parse dependencies from composer.lock")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreateSymfonyDemo(t *testing.T) {
	dir, src := useFixture(t, "test7-symfony-demo")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test Symfony demo specific fields
	assert.Equal(t, "composer", out.AnalysisInfo.PackageManager)
	assert.Equal(t, "symfony/demo", out.AnalysisInfo.ProjectName)
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion)

	// Test that we have the default workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Test framework detection should identify Symfony
	assert.Equal(t, "Symfony", out.AnalysisInfo.Extra.Framework)

	assert.NotEmpty(t, defaultWs.Dependencies, "Should parse dependencies from composer.lock")

	writeJSON(out, filepath.Join(src, "sbom.json"))
}

func TestCreateCachet(t *testing.T) {
	dir, src := useFixture(t, "test8-cachet")
	out := plugin.Start(dir, uuid.UUID{}, nil)

	// Basic assertions
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Test workspace
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")

	// Debug output
	t.Logf("=== SBOM Debug Info ===")
	t.Logf("Project Name: %s", out.AnalysisInfo.ProjectName)
	t.Logf("Package Manager: %s", out.AnalysisInfo.PackageManager)
	t.Logf("Framework: %s", out.AnalysisInfo.Extra.Framework)
	t.Logf("PHP Version: %s", out.AnalysisInfo.Extra.PHPVersion)
	t.Logf("Number of Dependencies: %d", len(defaultWs.Dependencies))
	t.Logf("Number of Dev Dependencies: %d", len(defaultWs.Start.DevDependencies))

	// Print first few dependencies if any
	if len(defaultWs.Dependencies) > 0 {
		t.Logf("\nFirst 5 dependencies:")
		count := 0
		for pkgName, versions := range defaultWs.Dependencies {
			if count >= 5 {
				break
			}
			// Get first version from the versions map
			for versionKey := range versions {
				t.Logf("  - %s: %s", pkgName, versionKey)
				break
			}
			count++
		}
	} else {
		t.Errorf("SBOM has 0 dependencies - this may indicate a parsing issue")
	}

	// Write output for inspection
	writeJSON(out, filepath.Join(src, "sbom.json"))
}
