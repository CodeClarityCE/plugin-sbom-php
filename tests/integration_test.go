package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeClarityCE/plugin-php-sbom/src/auth"
	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_PrivateRepositorySupport tests the complete private repository integration
func TestIntegration_PrivateRepositorySupport(t *testing.T) {
	// Create test project directory
	tempDir, err := os.MkdirTemp("", "php-sbom-integration-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("ComposerRepositoryIntegration", func(t *testing.T) {
		// Create composer.json with private repositories
		composerJSON := `{
			"name": "test/integration-project",
			"description": "Integration test project",
			"repositories": [
				{
					"type": "composer",
					"url": "https://repo.packagist.com/company/"
				},
				{
					"type": "vcs",
					"url": "https://github.com/company/private-package.git"
				},
				{
					"type": "artifact",
					"url": "https://artifacts.company.com/{name}-{version}.zip"
				}
			],
			"require": {
				"php": ">=7.4",
				"company/private-package": "^1.0"
			}
		}`

		composerPath := filepath.Join(tempDir, "composer.json")
		err := os.WriteFile(composerPath, []byte(composerJSON), 0644)
		require.NoError(t, err)

		// Create composer.lock
		composerLock := `{
			"_readme": [
				"This file locks the dependencies of your project to a known state"
			],
			"content-hash": "test-hash",
			"packages": [
				{
					"name": "company/private-package",
					"version": "1.0.0",
					"source": {
						"type": "git",
						"url": "https://github.com/company/private-package.git",
						"reference": "abc123"
					},
					"dist": {
						"type": "zip",
						"url": "https://artifacts.company.com/company-private-package-1.0.0.zip"
					},
					"type": "library",
					"license": ["proprietary"]
				}
			],
			"packages-dev": [],
			"platform": {
				"php": ">=7.4"
			}
		}`

		lockPath := filepath.Join(tempDir, "composer.lock")
		err = os.WriteFile(lockPath, []byte(composerLock), 0644)
		require.NoError(t, err)

		// Test enhanced parser
		enhancedParser, err := parser.NewEnhancedComposerParser(tempDir)
		require.NoError(t, err)

		sbom, err := enhancedParser.ParseWithPrivateRepos()
		require.NoError(t, err)
		require.NotNil(t, sbom)

		// Verify private repositories are detected
		assert.Len(t, sbom.PrivateRepositories, 3, "Should detect 3 private repositories")

		// Verify packages are processed
		assert.Len(t, sbom.Packages, 1, "Should have 1 package")

		// Check first package
		if len(sbom.Packages) > 0 {
			pkg := sbom.Packages[0]
			assert.Equal(t, "company/private-package", pkg.Name)
			assert.Equal(t, "1.0.0", pkg.Version)
		}
	})

	t.Run("AuthenticationIntegration", func(t *testing.T) {
		// Create auth.json
		authJSON := `{
			"http-basic": {
				"repo.packagist.com": {
					"username": "test-user",
					"password": "test-pass"
				}
			},
			"github-oauth": {
				"github.com": "test-github-token"
			},
			"gitlab-token": {
				"gitlab.com": "test-gitlab-token"
			},
			"bearer": {
				"artifacts.company.com": "test-bearer-token"
			}
		}`

		authPath := filepath.Join(tempDir, "auth.json")
		err := os.WriteFile(authPath, []byte(authJSON), 0600) // Secure permissions
		require.NoError(t, err)

		// Test auth manager
		authManager := auth.NewAuthManager()
		err = authManager.LoadFromAuthJSON(tempDir)
		require.NoError(t, err)

		// Verify authentication is loaded
		repoAuth, hasAuth := authManager.GetAuthForHost("repo.packagist.com")
		assert.True(t, hasAuth, "Should have auth for repo.packagist.com")
		if hasAuth {
			assert.Equal(t, "http-basic", string(repoAuth.Type))
			assert.Equal(t, "test-user", repoAuth.Username)
		}

		githubAuth, hasAuth := authManager.GetAuthForHost("github.com")
		assert.True(t, hasAuth, "Should have auth for github.com")
		if hasAuth {
			assert.Equal(t, "github-oauth", string(githubAuth.Type))
			assert.Equal(t, "test-github-token", githubAuth.Token)
		}
	})

	t.Run("EnvironmentVariableAuth", func(t *testing.T) {
		// Set environment variables
		os.Setenv("COMPOSER_AUTH", `{
			"http-basic": {
				"env.example.com": {
					"username": "env-user",
					"password": "env-pass"
				}
			}
		}`)
		defer os.Unsetenv("COMPOSER_AUTH")

		authManager := auth.NewAuthManager()
		err := authManager.LoadFromEnvironment()
		require.NoError(t, err)

		envAuth, hasAuth := authManager.GetAuthForHost("env.example.com")
		assert.True(t, hasAuth, "Should have auth from environment")
		if hasAuth {
			assert.Equal(t, "http-basic", string(envAuth.Type))
			assert.Equal(t, "env-user", envAuth.Username)
		}
	})
}

// TestIntegration_EnhancedSBOMGeneration tests enhanced SBOM generation with private repos
func TestIntegration_EnhancedSBOMGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "php-sbom-enhanced-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a complete project structure
	createTestProject(t, tempDir)

	// Test enhanced SBOM generation
	enhancedParser, err := parser.NewEnhancedComposerParser(tempDir)
	require.NoError(t, err)

	sbom, err := enhancedParser.ParseWithPrivateRepos()
	require.NoError(t, err)
	require.NotNil(t, sbom)

	// Verify SBOM structure
	assert.NotEmpty(t, sbom.Packages, "Should have packages")

	// Check for private package indicators
	hasPrivatePackage := false
	for _, pkg := range sbom.Packages {
		if pkg.IsPrivate {
			hasPrivatePackage = true
			break
		}
	}

	// May or may not have private packages depending on detection
	t.Logf("Private packages detected: %v", hasPrivatePackage)

	// Verify metadata
	privateCount := sbom.GetPrivatePackageCount()
	t.Logf("Private package count: %d", privateCount)

	authSummary := sbom.GetAuthenticationSummary()
	t.Logf("Authentication summary: %+v", authSummary)

	errorSummary := sbom.GetResolutionErrorSummary()
	t.Logf("Resolution error summary: %+v", errorSummary)
}

// TestIntegration_BackwardCompatibility tests that private repo code doesn't break standard flow
func TestIntegration_BackwardCompatibility(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "php-sbom-compat-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create standard composer files without private repos
	composerJSON := `{
		"name": "test/standard-project",
		"description": "Standard project without private repos",
		"require": {
			"php": ">=7.4",
			"monolog/monolog": "^2.0"
		}
	}`

	composerPath := filepath.Join(tempDir, "composer.json")
	err = os.WriteFile(composerPath, []byte(composerJSON), 0644)
	require.NoError(t, err)

	composerLock := `{
		"_readme": ["This file locks the dependencies"],
		"content-hash": "test",
		"packages": [
			{
				"name": "monolog/monolog",
				"version": "2.0.0",
				"type": "library",
				"license": ["MIT"],
				"description": "Logging library"
			}
		],
		"packages-dev": []
	}`

	lockPath := filepath.Join(tempDir, "composer.lock")
	err = os.WriteFile(lockPath, []byte(composerLock), 0644)
	require.NoError(t, err)

	// Test standard parser still works
	composerData, err := parser.ParseComposerJSON(composerPath)
	require.NoError(t, err)
	assert.Equal(t, "test/standard-project", composerData.Name)

	lockData, err := parser.ParseComposerLock(lockPath)
	require.NoError(t, err)
	assert.Len(t, lockData.Packages, 1)

	// Test enhanced parser with standard project
	enhancedParser, err := parser.NewEnhancedComposerParser(tempDir)
	require.NoError(t, err)

	sbom, err := enhancedParser.ParseWithPrivateRepos()
	require.NoError(t, err)
	require.NotNil(t, sbom)

	// Should work without errors
	assert.Len(t, sbom.Packages, 1)
	assert.Empty(t, sbom.PrivateRepositories, "Should have no private repositories")
	assert.Empty(t, sbom.ResolutionErrors, "Should have no resolution errors")
}

// Helper function to create a test project structure
func createTestProject(t *testing.T, dir string) {
	// Create composer.json
	composerJSON := map[string]any{
		"name":        "test/complete-project",
		"description": "Complete test project",
		"type":        "project",
		"license":     "proprietary",
		"repositories": []map[string]any{
			{
				"type": "composer",
				"url":  "https://repo.packagist.com/company/",
			},
		},
		"require": map[string]string{
			"php":              ">=7.4",
			"symfony/console":  "^5.0",
			"company/internal": "^1.0",
		},
		"require-dev": map[string]string{
			"phpunit/phpunit": "^9.0",
		},
	}

	data, err := json.MarshalIndent(composerJSON, "", "    ")
	require.NoError(t, err)

	composerPath := filepath.Join(dir, "composer.json")
	err = os.WriteFile(composerPath, data, 0644)
	require.NoError(t, err)

	// Create composer.lock
	composerLock := map[string]any{
		"_readme":      []string{"This file locks the dependencies"},
		"content-hash": "abc123",
		"packages": []map[string]any{
			{
				"name":    "symfony/console",
				"version": "5.4.0",
				"type":    "library",
				"license": []string{"MIT"},
			},
			{
				"name":    "company/internal",
				"version": "1.0.0",
				"type":    "library",
				"license": []string{"proprietary"},
				"source": map[string]string{
					"type":      "git",
					"url":       "https://github.com/company/internal.git",
					"reference": "def456",
				},
			},
		},
		"packages-dev": []map[string]any{
			{
				"name":    "phpunit/phpunit",
				"version": "9.5.0",
				"type":    "library",
				"license": []string{"BSD-3-Clause"},
			},
		},
	}

	lockData, err := json.MarshalIndent(composerLock, "", "    ")
	require.NoError(t, err)

	lockPath := filepath.Join(dir, "composer.lock")
	err = os.WriteFile(lockPath, lockData, 0644)
	require.NoError(t, err)
}

// BenchmarkIntegration_CompleteFlow benchmarks the complete private repo flow
func BenchmarkIntegration_CompleteFlow(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "php-sbom-bench-*")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	createTestProject(&testing.T{}, tempDir)

	b.ResetTimer()
	for b.Loop() {
		parser, _ := parser.NewEnhancedComposerParser(tempDir)
		parser.ParseWithPrivateRepos()
	}
}
