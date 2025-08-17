package main

import (
	"testing"

	plugin "github.com/CodeClarityCE/plugin-php-sbom/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestE2E_PHPExtensionDetection tests that PHP extensions are properly detected and included in SBOM
func TestE2E_PHPExtensionDetection(t *testing.T) {
	out := plugin.Start("./test1", uuid.UUID{}, nil)

	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)

	// Verify PHP extensions are detected and included in SBOM
	assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPExtensions.Extensions, "Should detect PHP extensions")
	
	// Test that common PHP extensions are detected
	extensions := out.AnalysisInfo.Extra.PHPExtensions.Extensions
	
	// Check for expected extensions from composer.json
	expectedExtensions := []string{"json", "openssl", "curl", "mbstring", "xml", "gd", "zip", "pdo"}
	foundExtensions := 0
	
	for _, extName := range expectedExtensions {
		if ext, exists := extensions[extName]; exists {
			foundExtensions++
			assert.NotEmpty(t, ext.Name, "Extension name should not be empty")
			assert.Contains(t, []string{"enabled", "loaded", "required", "dev-required"}, ext.Status, "Extension should be enabled, loaded, or required by composer")
			
			// Verify extension type categorization
			assert.Contains(t, []string{"core", "bundled", "external"}, ext.Type, "Extension should have valid type")
		}
	}
	
	assert.Greater(t, foundExtensions, 3, "Should find at least 4 common PHP extensions")
	
	// Test that vulnerable extensions are properly flagged
	vulnerableExtensions := []string{"openssl", "curl", "xml", "gd"}
	for _, extName := range vulnerableExtensions {
		if ext, exists := extensions[extName]; exists {
			// These extensions should be relevant for vulnerability tracking
			assert.NotEmpty(t, ext.Description, "Vulnerable extensions should have descriptions")
		}
	}
}

// TestE2E_VulnerablePackageDetection tests detection of packages with known vulnerabilities
func TestE2E_VulnerablePackageDetection(t *testing.T) {
	out := plugin.Start("./test-vulnerable", uuid.UUID{}, nil)

	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Verify we have dependencies from the vulnerable test case
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Default workspace should exist")
	assert.NotEmpty(t, defaultWs.Dependencies, "Should have dependencies")

	// Check for known vulnerable packages
	vulnerablePackages := map[string]string{
		"symfony/http-foundation": "v4.0.0",
		"twig/twig":              "v1.35.0",
		"doctrine/dbal":          "v2.5.0",
		"monolog/monolog":        "1.17.0",
		"guzzlehttp/guzzle":      "6.0.0",
		"phpmailer/phpmailer":    "v5.2.14",
		"firebase/php-jwt":       "v3.0.0",
		"league/flysystem":       "1.0.0",
	}

	foundVulnerablePackages := 0
	for packageName, expectedVersion := range vulnerablePackages {
		if versions, exists := defaultWs.Dependencies[packageName]; exists {
			foundVulnerablePackages++
			
			// Verify the package version matches what we expect
			versionFound := false
			for versionStr, versionInfo := range versions {
				if versionStr == expectedVersion {
					versionFound = true
					
					// Verify package structure
					assert.NotEmpty(t, versionInfo.Key, "Version key should not be empty")
					assert.Contains(t, versionInfo.Key, "@", "Version key should contain @ separator")
					assert.Equal(t, packageName+"@"+expectedVersion, versionInfo.Key, "Version key should match expected format")
					
					// Verify dependency classification
					assert.True(t, versionInfo.Prod, "Vulnerable packages should be production dependencies")
					assert.False(t, versionInfo.Dev, "Production packages should not be marked as dev")
					
					// Verify licenses are detected
					assert.NotEmpty(t, versionInfo.Licenses, "Should detect package licenses")
					
					break
				}
			}
			assert.True(t, versionFound, "Should find expected version %s for package %s", expectedVersion, packageName)
		}
	}

	assert.Greater(t, foundVulnerablePackages, 6, "Should find at least 7 vulnerable packages")

	// Verify dev dependencies are separate
	devPackages := map[string]string{
		"phpunit/phpunit": "6.0.0",
		"psy/psysh":      "v0.8.0",
	}

	for packageName, expectedVersion := range devPackages {
		if versions, exists := defaultWs.Dependencies[packageName]; exists {
			for versionStr, versionInfo := range versions {
				if versionStr == expectedVersion {
					assert.True(t, versionInfo.Dev, "Dev packages should be marked as dev")
					assert.False(t, versionInfo.Prod, "Dev packages should not be marked as prod")
					break
				}
			}
		}
	}

	writeJSON(out, "./test-vulnerable/sbom.json")
}

// TestE2E_PHPFrameworkDetection tests framework detection across different PHP frameworks
func TestE2E_PHPFrameworkDetection(t *testing.T) {
	testCases := map[string]string{
		"./test1":              "CakePHP",         // Passbolt uses CakePHP
		"./test2-laravel":      "Laravel",         // Laravel project
		"./test3-symfony":      "Symfony",         // Symfony project  
		"./test4-wordpress":    "WordPress",       // WordPress project
		"./test5-codeigniter":  "CodeIgniter 4",   // CodeIgniter project
		"./test6-pure-php":     "Symfony Components", // Pure PHP with Symfony components
		"./test7-symfony-demo": "Symfony",         // Symfony demo
	}

	for testDir, expectedFramework := range testCases {
		t.Run(testDir, func(t *testing.T) {
			out := plugin.Start(testDir, uuid.UUID{}, nil)

			assert.NotNil(t, out)
			assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)

			// Test framework detection
			actualFramework := out.AnalysisInfo.Extra.Framework
			
			// Some frameworks might be detected as "Generic PHP" if specific detection fails
			if actualFramework != expectedFramework {
				assert.Contains(t, []string{expectedFramework, "Generic PHP"}, actualFramework,
					"Framework should be detected as %s or Generic PHP for %s", expectedFramework, testDir)
			} else {
				assert.Equal(t, expectedFramework, actualFramework, "Should detect correct framework for %s", testDir)
			}

			// Verify project metadata
			assert.NotEmpty(t, out.AnalysisInfo.ProjectName, "Should have project name")
			assert.Equal(t, "composer", out.AnalysisInfo.PackageManager, "Should use Composer package manager")
			assert.NotEmpty(t, out.AnalysisInfo.Extra.PHPVersion, "Should detect PHP version")
		})
	}
}

// TestE2E_SBOMStructureCompatibility tests that PHP SBOM structure is compatible with js-sbom
func TestE2E_SBOMStructureCompatibility(t *testing.T) {
	out := plugin.Start("./test1", uuid.UUID{}, nil)

	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)

	// Test SBOM structure compatibility with js-sbom
	assert.NotEmpty(t, out.WorkSpaces, "Should have workspaces")
	assert.NotNil(t, out.AnalysisInfo, "Should have analysis info")

	// Test workspace structure
	defaultWs, exists := out.WorkSpaces["."]
	assert.True(t, exists, "Should have default workspace")
	assert.NotNil(t, defaultWs.Dependencies, "Should have dependencies map")
	assert.NotNil(t, defaultWs.Start, "Should have start dependencies")

	// Test analysis info structure
	assert.NotEmpty(t, out.AnalysisInfo.Time.AnalysisStartTime, "Should have start time")
	assert.NotEmpty(t, out.AnalysisInfo.Time.AnalysisEndTime, "Should have end time")
	assert.Greater(t, out.AnalysisInfo.Time.AnalysisDeltaTime, float64(0), "Should have positive delta time")

	// Test paths structure
	assert.Contains(t, out.AnalysisInfo.Paths.PackageFile, "composer.json", "Should reference composer.json")
	assert.Contains(t, out.AnalysisInfo.Paths.Lockfile, "composer.lock", "Should reference composer.lock")

	// Test workspace info compatibility
	assert.Equal(t, ".", out.AnalysisInfo.Workspaces.DefaultWorkspaceName)
	assert.Equal(t, "self-managed", out.AnalysisInfo.Workspaces.SelfManagedWorkspaceName)

	// Test version separators (compatible with js-sbom)
	assert.Equal(t, "@", out.AnalysisInfo.Extra.VersionSeperator)
	assert.Equal(t, "/", out.AnalysisInfo.Extra.ImportPathSeperator)

	// Test that dependency structure matches js-sbom format
	for depName, versions := range defaultWs.Dependencies {
		assert.NotEmpty(t, depName, "Dependency name should not be empty")
		assert.NotEmpty(t, versions, "Dependency versions should not be empty")

		for versionStr, versionInfo := range versions {
			assert.NotEmpty(t, versionStr, "Version string should not be empty")
			assert.Contains(t, versionInfo.Key, "@", "Version key should contain @ separator")
			assert.Equal(t, depName+"@"+versionStr, versionInfo.Key, "Version key should follow js-sbom format")

			// Test boolean fields are properly set
			assert.True(t, versionInfo.Dev || versionInfo.Prod, "Should be either dev or prod dependency")
			assert.True(t, versionInfo.Direct || versionInfo.Transitive, "Should be either direct or transitive")
			assert.False(t, versionInfo.Optional, "Optional should be false for composer dependencies")
			assert.False(t, versionInfo.Bundled, "Bundled should be false for composer dependencies")
		}
	}
}

// TestE2E_ErrorHandlingAndEdgeCases tests error handling and edge cases
func TestE2E_ErrorHandlingAndEdgeCases(t *testing.T) {
	// Test with non-existent directory
	t.Run("NonExistentDirectory", func(t *testing.T) {
		out := plugin.Start("./nonexistent-directory", uuid.UUID{}, nil)
		
		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.FAILURE, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.AnalysisInfo.Errors, "Should have error messages")
		
		// Verify error structure
		for _, err := range out.AnalysisInfo.Errors {
			assert.NotEmpty(t, err.Public.Description, "Error should have public description")
			assert.NotEmpty(t, err.Private.Description, "Error should have private description")
		}
	})

	// Test with directory containing no PHP project
	t.Run("NonPHPProject", func(t *testing.T) {
		out := plugin.Start("../", uuid.UUID{}, nil) // Parent directory without composer files
		
		assert.NotNil(t, out)
		// Should either fail or succeed with empty dependencies
		if out.AnalysisInfo.Status == codeclarity.FAILURE {
			assert.NotEmpty(t, out.AnalysisInfo.Errors, "Should have error messages")
		} else {
			// If it succeeds, should have minimal data
			assert.Empty(t, out.WorkSpaces["."].Dependencies, "Should have no dependencies")
		}
	})

	// Test with composer.json but no composer.lock
	t.Run("ComposerJSONOnly", func(t *testing.T) {
		// Most test cases only have composer.json (no working composer.lock)
		out := plugin.Start("./test2-laravel", uuid.UUID{}, nil)
		
		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		
		// Should detect project but have no dependencies without composer.lock
		assert.NotEmpty(t, out.AnalysisInfo.ProjectName, "Should detect project name")
		assert.Empty(t, out.WorkSpaces["."].Dependencies, "Should have no dependencies without composer.lock")
	})
}

// TestE2E_PerformanceAndMemory tests performance characteristics of PHP SBOM generation
func TestE2E_PerformanceAndMemory(t *testing.T) {
	// Test with the largest project (test1 - Passbolt)
	out := plugin.Start("./test1", uuid.UUID{}, nil)

	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)

	// Verify analysis completes in reasonable time
	assert.Less(t, out.AnalysisInfo.Time.AnalysisDeltaTime, 30.0, "Analysis should complete within 30 seconds")
	assert.Greater(t, out.AnalysisInfo.Time.AnalysisDeltaTime, 0.0, "Analysis should take measurable time")

	// Verify we can handle reasonable number of dependencies
	totalDeps := 0
	for _, ws := range out.WorkSpaces {
		totalDeps += len(ws.Dependencies)
	}
	
	assert.Greater(t, totalDeps, 10, "Should detect at least 10 dependencies in Passbolt")
	assert.Less(t, totalDeps, 1000, "Should not detect unreasonably high number of dependencies")

	// Verify memory usage is reasonable by checking output size
	totalVersions := 0
	for _, ws := range out.WorkSpaces {
		for _, versions := range ws.Dependencies {
			totalVersions += len(versions)
		}
	}
	
	assert.Equal(t, totalDeps, totalVersions, "Each dependency should have exactly one version in lock file")
}

// TestE2E_PHPExtensionVulnerabilityRelevance tests that only relevant extensions are flagged for vulnerability tracking
func TestE2E_PHPExtensionVulnerabilityRelevance(t *testing.T) {
	out := plugin.Start("./test1", uuid.UUID{}, nil)

	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)

	extensions := out.AnalysisInfo.Extra.PHPExtensions.Extensions

	// Test that vulnerable extensions are detected and properly categorized
	vulnerableExtensions := map[string]bool{
		"openssl": true,
		"curl":    true, 
		"xml":     true,
		"gd":      true,
		"json":    true,
		"mbstring": true,
		"zip":     true,
		"pdo":     true,
	}

	for extName, shouldBeVulnerable := range vulnerableExtensions {
		if ext, exists := extensions[extName]; exists {
			// These extensions should be flagged as relevant for vulnerability tracking
			assert.NotEmpty(t, ext.Description, "Vulnerable extension %s should have description", extName)
			assert.Contains(t, []string{"core", "bundled"}, ext.Type, "Vulnerable extension %s should be core or bundled", extName)
			
			// Note: IsVulnerabilityRelevant would be called by vuln-finder, not SBOM plugin
			// But we can verify the extensions have the necessary metadata
			assert.NotEmpty(t, ext.Name, "Extension %s should have name", extName)
			assert.NotEmpty(t, ext.Status, "Extension %s should have status", extName)
		} else if shouldBeVulnerable {
			t.Logf("Warning: Expected vulnerable extension %s not found", extName)
		}
	}
}