package main

import (
	"testing"

	plugin "github.com/CodeClarityCE/plugin-php-sbom/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreatePassbolt(t *testing.T) {
	out := plugin.Start("./test1", uuid.UUID{}, nil)

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

	writeJSON(out, "./test1/sbom.json")
}

func TestCreateTest1EdgeCases(t *testing.T) {
	out := plugin.Start("./test1", uuid.UUID{}, nil)

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

func TestComposerJSONOnly(t *testing.T) {
	// This would test a project with only composer.json (no composer.lock)
	// For now, we'll skip this test as we don't have that test case
	t.Skip("Test case for composer.json-only project not available yet")
}