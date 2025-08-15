package parser

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ComposerJSON represents the structure of composer.json
type ComposerJSON struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Version     string                 `json:"version"`
	License     any            `json:"license"` // Can be string or array
	Require     map[string]string      `json:"require"`
	RequireDev  map[string]string      `json:"require-dev"`
	Autoload    map[string]any `json:"autoload"`
	Authors     []Author               `json:"authors"`
	Extra       map[string]any `json:"extra"`
}

// Author represents a package author
type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// ComposerLock represents the structure of composer.lock
type ComposerLock struct {
	Readme          []string         `json:"_readme"`
	ContentHash     string           `json:"content-hash"`
	Packages        []PackageInfo    `json:"packages"`
	PackagesDev     []PackageInfo    `json:"packages-dev"`
	Aliases         []any    `json:"aliases"`
	MinimumStability string          `json:"minimum-stability"`
	StabilityFlags  map[string]int   `json:"stability-flags"`
	PreferStable    bool             `json:"prefer-stable"`
	PreferLowest    bool             `json:"prefer-lowest"`
	Platform        map[string]string `json:"platform"`
	PlatformDev     []any    `json:"platform-dev"` // Can be array or map
	PluginAPIVersion string          `json:"plugin-api-version"`
}

// PackageInfo represents a package in composer.lock
type PackageInfo struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Source          Source                 `json:"source"`
	Dist            Dist                   `json:"dist"`
	Require         map[string]string      `json:"require"`
	RequireDev      map[string]string      `json:"require-dev"`
	Type            string                 `json:"type"`
	License         any            `json:"license"`
	Authors         []Author               `json:"authors"`
	Description     string                 `json:"description"`
	Keywords        []string               `json:"keywords"`
	Time            string                 `json:"time"`
	Autoload        map[string]any `json:"autoload"`
	NotificationURL string                 `json:"notification-url"`
	Extra           map[string]any `json:"extra"`
}

// Source represents the source control info
type Source struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

// Dist represents the distribution info
type Dist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum"`
}

// ParseComposerJSON parses a composer.json file
func ParseComposerJSON(filePath string) (*ComposerJSON, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.json: %w", err)
	}

	var composerJSON ComposerJSON
	if err := json.Unmarshal(data, &composerJSON); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	return &composerJSON, nil
}

// ParseComposerLock parses a composer.lock file
func ParseComposerLock(filePath string) (*ComposerLock, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.lock: %w", err)
	}

	var composerLock ComposerLock
	if err := json.Unmarshal(data, &composerLock); err != nil {
		return nil, fmt.Errorf("failed to parse composer.lock: %w", err)
	}

	return &composerLock, nil
}

// FindComposerFiles searches for composer.json and composer.lock in a directory
func FindComposerFiles(rootDir string) ([]string, []string, error) {
	var composerJSONFiles []string
	var composerLockFiles []string

	log.Printf("FindComposerFiles Debug - searching in: %s", rootDir)
	
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor directories
		if info.IsDir() && info.Name() == "vendor" {
			return filepath.SkipDir
		}

		// Skip node_modules directories (in case of mixed projects)
		if info.IsDir() && info.Name() == "node_modules" {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			if info.Name() == "composer.json" {
				composerJSONFiles = append(composerJSONFiles, path)
			} else if info.Name() == "composer.lock" {
				composerLockFiles = append(composerLockFiles, path)
			}
		}

		return nil
	})

	return composerJSONFiles, composerLockFiles, err
}

// FindPHARFiles searches for PHAR archives in a directory
func FindPHARFiles(rootDir string) ([]string, error) {
	var pharFiles []string

	log.Printf("FindPHARFiles Debug - searching for PHAR archives in: %s", rootDir)
	
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor and node_modules directories
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == "node_modules") {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			// Check for .phar files
			if strings.HasSuffix(strings.ToLower(info.Name()), ".phar") {
				pharFiles = append(pharFiles, path)
				log.Printf("Found PHAR file: %s", path)
			}
		}

		return nil
	})

	return pharFiles, err
}

// PHARInfo represents information about a PHAR archive
type PHARInfo struct {
	Path        string                 `json:"path"`
	Name        string                 `json:"name"`
	Size        int64                  `json:"size"`
	Modified    string                 `json:"modified"`
	Signature   string                 `json:"signature"`
	Metadata    map[string]interface{} `json:"metadata"`
	MainScript  string                 `json:"main_script"`
	IsExecutable bool                  `json:"is_executable"`
}

// AnalyzePHARFile analyzes a PHAR archive and extracts metadata
func AnalyzePHARFile(pharPath string) (*PHARInfo, error) {
	info, err := os.Stat(pharPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat PHAR file: %w", err)
	}

	pharInfo := &PHARInfo{
		Path:        pharPath,
		Name:        filepath.Base(pharPath),
		Size:        info.Size(),
		Modified:    info.ModTime().Format("2006-01-02T15:04:05Z"),
		Metadata:    make(map[string]interface{}),
		IsExecutable: isExecutable(pharPath),
	}

	// Try to extract basic information about the PHAR
	// Note: This is a simplified implementation. In production, you might want
	// to use actual PHAR reading libraries or external tools
	log.Printf("Analyzing PHAR file: %s (size: %d bytes)", pharPath, info.Size())

	return pharInfo, nil
}

// isExecutable checks if a file has executable permissions
func isExecutable(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}

// GetPackageName extracts the package name from Packagist format (vendor/package)
func GetPackageName(fullName string) (vendor string, pkg string) {
	parts := strings.Split(fullName, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", fullName
}

// NormalizeLicense converts license field to string array
func NormalizeLicense(license any) []string {
	switch v := license.(type) {
	case string:
		return []string{v}
	case []any:
		var licenses []string
		for _, l := range v {
			if str, ok := l.(string); ok {
				licenses = append(licenses, str)
			}
		}
		return licenses
	default:
		return []string{}
	}
}