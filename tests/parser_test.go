package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test data for parser unit tests
var testComposerJSON = `{
    "name": "test/package",
    "type": "library",
    "description": "A test package for unit testing",
    "license": "MIT",
    "version": "1.0.0",
    "authors": [
        {
            "name": "Test Author",
            "email": "test@example.com",
            "role": "Developer"
        }
    ],
    "require": {
        "php": ">=8.1",
        "symfony/console": "^6.0",
        "doctrine/orm": "^2.12"
    },
    "require-dev": {
        "phpunit/phpunit": "^9.5",
        "phpstan/phpstan": "^1.8"
    },
    "autoload": {
        "psr-4": {
            "Test\\": "src/"
        }
    }
}`

var testComposerLock = `{
    "_readme": [
        "This file locks the dependencies of your project to a known state"
    ],
    "content-hash": "test-hash-12345",
    "packages": [
        {
            "name": "symfony/console",
            "version": "v6.2.5",
            "source": {
                "type": "git",
                "url": "https://github.com/symfony/console.git",
                "reference": "abc123def456"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/symfony/console/zipball/abc123def456",
                "reference": "abc123def456",
                "shasum": ""
            },
            "require": {
                "php": ">=8.1",
                "symfony/deprecation-contracts": "^2.1|^3",
                "symfony/polyfill-mbstring": "~1.0",
                "symfony/service-contracts": "^1.1|^2|^3",
                "symfony/string": "^5.4|^6.0"
            },
            "type": "library",
            "license": ["MIT"],
            "authors": [
                {
                    "name": "Fabien Potencier",
                    "email": "fabien@symfony.com"
                }
            ],
            "description": "Eases the creation of beautiful and testable command line interfaces",
            "keywords": ["cli", "command line", "console", "terminal"]
        },
        {
            "name": "doctrine/orm",
            "version": "2.14.1",
            "source": {
                "type": "git",
                "url": "https://github.com/doctrine/orm.git",
                "reference": "def456abc789"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/doctrine/orm/zipball/def456abc789",
                "reference": "def456abc789",
                "shasum": ""
            },
            "require": {
                "php": "^7.1 || ^8.0",
                "doctrine/cache": "^1.12.1 || ^2.1.1",
                "doctrine/collections": "^1.5 || ^2.0",
                "doctrine/common": "^3.0.3",
                "doctrine/dbal": "^2.13.1 || ^3.2",
                "doctrine/deprecations": "^0.5.3 || ^1.0",
                "doctrine/event-manager": "^1.1",
                "doctrine/inflector": "^1.4 || ^2.0",
                "doctrine/instantiator": "^1.3",
                "doctrine/lexer": "^1.2",
                "doctrine/persistence": "^2.4 || ^3.0",
                "psr/cache": "^1 || ^2 || ^3",
                "symfony/console": "^3.0 || ^4.0 || ^5.0 || ^6.0"
            },
            "type": "library",
            "license": ["MIT"],
            "authors": [
                {
                    "name": "Guilherme Blanco",
                    "email": "guilhermeblanco@gmail.com"
                },
                {
                    "name": "Roman Borschel",
                    "email": "roman@code-factory.org"
                }
            ],
            "description": "Object-Relational-Mapping for PHP",
            "keywords": ["database", "orm"]
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "9.6.4",
            "source": {
                "type": "git",
                "url": "https://github.com/sebastianbergmann/phpunit.git",
                "reference": "ghi789jkl012"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/sebastianbergmann/phpunit/zipball/ghi789jkl012",
                "reference": "ghi789jkl012",
                "shasum": ""
            },
            "require": {
                "ext-dom": "*",
                "ext-json": "*",
                "ext-libxml": "*",
                "ext-mbstring": "*",
                "ext-xml": "*",
                "ext-xmlwriter": "*",
                "myclabs/deep-copy": "^1.10.1",
                "phar-io/manifest": "^2.0.3",
                "phar-io/version": "^3.0.2",
                "php": ">=7.3",
                "phpspec/prophecy": "^1.12.1",
                "phpunit/php-code-coverage": "^9.2.13",
                "phpunit/php-file-iterator": "^3.0.5",
                "phpunit/php-invoker": "^3.1.1",
                "phpunit/php-text-template": "^2.0.3",
                "phpunit/php-timer": "^5.0.2",
                "sebastian/cli-parser": "^1.0.1",
                "sebastian/code-unit": "^1.0.6",
                "sebastian/comparator": "^4.0.5",
                "sebastian/diff": "^4.0.3",
                "sebastian/environment": "^5.1.3",
                "sebastian/exporter": "^4.0.3",
                "sebastian/global-state": "^5.0.1",
                "sebastian/object-enumerator": "^4.0.3",
                "sebastian/resource-operations": "^3.0.3",
                "sebastian/type": "^3.0",
                "sebastian/version": "^3.0.2"
            },
            "type": "library",
            "license": ["BSD-3-Clause"],
            "authors": [
                {
                    "name": "Sebastian Bergmann",
                    "email": "sebastian@phpunit.de",
                    "role": "lead"
                }
            ],
            "description": "The PHP Unit Testing framework.",
            "keywords": ["phpunit", "testing", "xunit"]
        }
    ],
    "aliases": [],
    "minimum-stability": "stable",
    "stability-flags": {},
    "prefer-stable": true,
    "prefer-lowest": false,
    "platform": {
        "php": ">=8.1"
    },
    "platform-dev": [],
    "plugin-api-version": "2.3.0"
}`

func TestParseComposerJSON(t *testing.T) {
	// Create temporary file with test data
	tempFile, err := os.CreateTemp("", "composer-test-*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString(testComposerJSON)
	require.NoError(t, err)
	tempFile.Close()

	// Test parsing
	result, err := parser.ParseComposerJSON(tempFile.Name())
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify parsed data
	assert.Equal(t, "test/package", result.Name)
	assert.Equal(t, "library", result.Type)
	assert.Equal(t, "A test package for unit testing", result.Description)
	assert.Equal(t, "MIT", result.License)
	assert.Equal(t, "1.0.0", result.Version)

	// Test require section
	assert.Equal(t, ">=8.1", result.Require["php"])
	assert.Equal(t, "^6.0", result.Require["symfony/console"])
	assert.Equal(t, "^2.12", result.Require["doctrine/orm"])

	// Test require-dev section
	assert.Equal(t, "^9.5", result.RequireDev["phpunit/phpunit"])
	assert.Equal(t, "^1.8", result.RequireDev["phpstan/phpstan"])

	// Test authors
	assert.Len(t, result.Authors, 1)
	assert.Equal(t, "Test Author", result.Authors[0].Name)
	assert.Equal(t, "test@example.com", result.Authors[0].Email)
	assert.Equal(t, "Developer", result.Authors[0].Role)
}

func TestParseComposerJSONInvalidFile(t *testing.T) {
	// Test with non-existent file
	_, err := parser.ParseComposerJSON("/nonexistent/composer.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read composer.json")
}

func TestParseComposerJSONInvalidJSON(t *testing.T) {
	// Create temporary file with invalid JSON
	tempFile, err := os.CreateTemp("", "composer-invalid-*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString(`{"name": "test", "invalid": json}`)
	require.NoError(t, err)
	tempFile.Close()

	// Test parsing
	_, err = parser.ParseComposerJSON(tempFile.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse composer.json")
}

func TestParseComposerLock(t *testing.T) {
	// Create temporary file with test data
	tempFile, err := os.CreateTemp("", "composer-lock-test-*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString(testComposerLock)
	require.NoError(t, err)
	tempFile.Close()

	// Test parsing
	result, err := parser.ParseComposerLock(tempFile.Name())
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify parsed data
	assert.Equal(t, "test-hash-12345", result.ContentHash)
	assert.Equal(t, "stable", result.MinimumStability)
	assert.True(t, result.PreferStable)
	assert.False(t, result.PreferLowest)
	assert.Equal(t, "2.3.0", result.PluginAPIVersion)

	// Test packages
	assert.Len(t, result.Packages, 2)
	
	// Test Symfony Console package
	symfonyPackage := result.Packages[0]
	assert.Equal(t, "symfony/console", symfonyPackage.Name)
	assert.Equal(t, "v6.2.5", symfonyPackage.Version)
	assert.Equal(t, "library", symfonyPackage.Type)
	assert.Equal(t, "git", symfonyPackage.Source.Type)
	assert.Equal(t, "https://github.com/symfony/console.git", symfonyPackage.Source.URL)
	assert.Contains(t, symfonyPackage.Description, "command line interfaces")

	// Test Doctrine ORM package
	doctrinePackage := result.Packages[1]
	assert.Equal(t, "doctrine/orm", doctrinePackage.Name)
	assert.Equal(t, "2.14.1", doctrinePackage.Version)
	assert.Equal(t, "library", doctrinePackage.Type)
	assert.Contains(t, doctrinePackage.Description, "Object-Relational-Mapping")

	// Test dev packages
	assert.Len(t, result.PackagesDev, 1)
	phpunitPackage := result.PackagesDev[0]
	assert.Equal(t, "phpunit/phpunit", phpunitPackage.Name)
	assert.Equal(t, "9.6.4", phpunitPackage.Version)
	assert.Contains(t, phpunitPackage.Description, "Unit Testing framework")

	// Test platform requirements
	assert.Equal(t, ">=8.1", result.Platform["php"])
}

func TestParseComposerLockInvalidFile(t *testing.T) {
	// Test with non-existent file
	_, err := parser.ParseComposerLock("/nonexistent/composer.lock")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read composer.lock")
}

func TestFindComposerFiles(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := os.MkdirTemp("", "composer-find-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files
	composerJSONPath := filepath.Join(tempDir, "composer.json")
	composerLockPath := filepath.Join(tempDir, "composer.lock")
	
	err = os.WriteFile(composerJSONPath, []byte("{}"), 0644)
	require.NoError(t, err)
	
	err = os.WriteFile(composerLockPath, []byte("{}"), 0644)
	require.NoError(t, err)

	// Create subdirectory with additional composer files
	subDir := filepath.Join(tempDir, "packages", "sub-package")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)
	
	subComposerJSON := filepath.Join(subDir, "composer.json")
	err = os.WriteFile(subComposerJSON, []byte("{}"), 0644)
	require.NoError(t, err)

	// Create vendor directory (should be skipped)
	vendorDir := filepath.Join(tempDir, "vendor")
	err = os.MkdirAll(vendorDir, 0755)
	require.NoError(t, err)
	
	vendorComposer := filepath.Join(vendorDir, "composer.json")
	err = os.WriteFile(vendorComposer, []byte("{}"), 0644)
	require.NoError(t, err)

	// Test finding composer files
	jsonFiles, lockFiles, err := parser.FindComposerFiles(tempDir)
	require.NoError(t, err)

	// Verify results
	assert.Len(t, jsonFiles, 2) // Should find 2 (root and sub-package, vendor skipped)
	assert.Len(t, lockFiles, 1) // Should find 1 (only root)

	// Verify paths are correct
	assert.Contains(t, jsonFiles, composerJSONPath)
	assert.Contains(t, jsonFiles, subComposerJSON)
	assert.Contains(t, lockFiles, composerLockPath)
	
	// Verify vendor files are not included
	assert.NotContains(t, jsonFiles, vendorComposer)
}

func TestFindPHARFiles(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "phar-find-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test PHAR files
	pharFile1 := filepath.Join(tempDir, "app.phar")
	pharFile2 := filepath.Join(tempDir, "tool.PHAR") // Test case insensitive
	regularFile := filepath.Join(tempDir, "script.php")

	err = os.WriteFile(pharFile1, []byte("test phar content"), 0644)
	require.NoError(t, err)
	
	err = os.WriteFile(pharFile2, []byte("another phar"), 0644)
	require.NoError(t, err)
	
	err = os.WriteFile(regularFile, []byte("<?php echo 'test';"), 0644)
	require.NoError(t, err)

	// Create vendor directory with PHAR (should be skipped)
	vendorDir := filepath.Join(tempDir, "vendor")
	err = os.MkdirAll(vendorDir, 0755)
	require.NoError(t, err)
	
	vendorPhar := filepath.Join(vendorDir, "vendor.phar")
	err = os.WriteFile(vendorPhar, []byte("vendor phar"), 0644)
	require.NoError(t, err)

	// Test finding PHAR files
	pharFiles, err := parser.FindPHARFiles(tempDir)
	require.NoError(t, err)

	// Verify results
	assert.Len(t, pharFiles, 2) // Should find 2 PHAR files (vendor skipped)
	assert.Contains(t, pharFiles, pharFile1)
	assert.Contains(t, pharFiles, pharFile2)
	assert.NotContains(t, pharFiles, vendorPhar)
	assert.NotContains(t, pharFiles, regularFile)
}

func TestGetPackageName(t *testing.T) {
	tests := []struct {
		fullName string
		vendor   string
		pkg      string
	}{
		{"symfony/console", "symfony", "console"},
		{"doctrine/orm", "doctrine", "orm"},
		{"laravel/framework", "laravel", "framework"},
		{"single-name", "", "single-name"},
		{"vendor/package/extra", "", "vendor/package/extra"},
	}

	for _, test := range tests {
		t.Run(test.fullName, func(t *testing.T) {
			vendor, pkg := parser.GetPackageName(test.fullName)
			assert.Equal(t, test.vendor, vendor)
			assert.Equal(t, test.pkg, pkg)
		})
	}
}

func TestNormalizeLicense(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "string license",
			input:    "MIT",
			expected: []string{"MIT"},
		},
		{
			name:     "array license",
			input:    []interface{}{"MIT", "GPL-2.0"},
			expected: []string{"MIT", "GPL-2.0"},
		},
		{
			name:     "nil license",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{""},
		},
		{
			name:     "empty array",
			input:    []interface{}{},
			expected: []string(nil),
		},
		{
			name:     "mixed array with empty strings",
			input:    []interface{}{"MIT", "", "GPL-2.0"},
			expected: []string{"MIT", "", "GPL-2.0"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := parser.NormalizeLicense(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestAnalyzePHARFile(t *testing.T) {
	// Create a simple test PHAR file
	tempDir, err := os.MkdirTemp("", "phar-analyze-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	pharFile := filepath.Join(tempDir, "test.phar")
	err = os.WriteFile(pharFile, []byte("test phar content"), 0644)
	require.NoError(t, err)

	// Test analyzing PHAR file
	pharInfo, err := parser.AnalyzePHARFile(pharFile)
	require.NoError(t, err)
	require.NotNil(t, pharInfo)

	// Verify basic info
	assert.Equal(t, pharFile, pharInfo.Path)
	assert.Equal(t, "test.phar", pharInfo.Name)
	assert.Equal(t, int64(17), pharInfo.Size) // Length of "test phar content"
	assert.NotEmpty(t, pharInfo.Modified)
	assert.False(t, pharInfo.IsExecutable) // File created without execute permission
}

func TestAnalyzePHARFileNonExistent(t *testing.T) {
	// Test with non-existent file
	_, err := parser.AnalyzePHARFile("/nonexistent/test.phar")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat PHAR file")
}