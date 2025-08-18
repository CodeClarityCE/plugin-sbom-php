package artifact

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeClarityCE/plugin-php-sbom/src/auth"
	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
)

// ArtifactResolver handles artifact-based repositories (ZIP files)
type ArtifactResolver struct {
	authManager *auth.AuthManager
	httpClient  *http.Client
	cacheDir    string
}

// ArtifactInfo represents information about an artifact
type ArtifactInfo struct {
	URL          string `json:"url"`
	LocalPath    string `json:"local_path"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Downloaded   bool   `json:"downloaded"`
	ExtractedDir string `json:"extracted_dir"`
}

// ComposerJSON represents basic composer.json structure for artifact resolution
type ComposerJSON struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Version     string                 `json:"version"`
	License     interface{}            `json:"license"`
	Authors     []Author               `json:"authors"`
	Require     map[string]string      `json:"require"`
	RequireDev  map[string]string      `json:"require-dev"`
}

// Author represents an author entry in composer.json
type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// NewArtifactResolver creates a new artifact repository resolver
func NewArtifactResolver(authManager *auth.AuthManager) *ArtifactResolver {
	cacheDir := filepath.Join(os.TempDir(), "php-sbom-artifact-cache")
	os.MkdirAll(cacheDir, 0755)

	return &ArtifactResolver{
		authManager: authManager,
		httpClient: &http.Client{
			Timeout: 120 * time.Second, // Longer timeout for large ZIP downloads
		},
		cacheDir: cacheDir,
	}
}

// ResolveArtifactRepository resolves package information from an artifact repository
func (ar *ArtifactResolver) ResolveArtifactRepository(repo auth.ComposerRepository, packageName, constraint string) (*types.PackageInfo, error) {
	log.Printf("Resolving package %s from artifact repository: %s", packageName, repo.URL)

	// Get list of available artifacts
	artifacts, err := ar.discoverArtifacts(repo, packageName)
	if err != nil {
		return nil, fmt.Errorf("failed to discover artifacts: %w", err)
	}

	// Find best matching artifact
	artifact, err := ar.selectBestArtifact(artifacts, packageName, constraint)
	if err != nil {
		return nil, fmt.Errorf("failed to select artifact: %w", err)
	}

	if artifact == nil {
		return nil, fmt.Errorf("no matching artifact found for package %s", packageName)
	}

	// Download and extract artifact
	if !artifact.Downloaded {
		if err := ar.downloadArtifact(repo, artifact); err != nil {
			return nil, fmt.Errorf("failed to download artifact: %w", err)
		}
	}

	// Extract package information
	packageInfo, err := ar.extractPackageInfo(artifact)
	if err != nil {
		return nil, fmt.Errorf("failed to extract package info: %w", err)
	}

	// Mark as private if from private repository
	if ar.authManager.IsPrivateRepository(repo) {
		packageInfo.IsPrivate = true
		packageInfo.Repository = repo.URL
	}

	log.Printf("Successfully resolved artifact package: %s@%s", packageInfo.Name, packageInfo.Version)
	return packageInfo, nil
}

// discoverArtifacts discovers available artifacts from the repository
func (ar *ArtifactResolver) discoverArtifacts(repo auth.ComposerRepository, packageName string) ([]*ArtifactInfo, error) {
	var artifacts []*ArtifactInfo

	// Check if it's a directory-based artifact repository
	if ar.isDirectoryRepository(repo.URL) {
		return ar.discoverDirectoryArtifacts(repo, packageName)
	}

	// Check if it's a URL pattern-based repository
	if ar.isURLPatternRepository(repo.URL) {
		return ar.discoverURLPatternArtifacts(repo, packageName)
	}

	// Check if it's a single ZIP file
	if ar.isZipFile(repo.URL) {
		artifact := &ArtifactInfo{
			URL:        repo.URL,
			Name:       packageName,
			Downloaded: false,
		}
		artifacts = append(artifacts, artifact)
		return artifacts, nil
	}

	return nil, fmt.Errorf("unsupported artifact repository type: %s", repo.URL)
}

// isDirectoryRepository checks if the repository is directory-based
func (ar *ArtifactResolver) isDirectoryRepository(url string) bool {
	// Directory repositories typically end with / and don't have file extensions
	return strings.HasSuffix(url, "/") && !strings.Contains(url, ".zip")
}

// isURLPatternRepository checks if the repository uses URL patterns
func (ar *ArtifactResolver) isURLPatternRepository(url string) bool {
	// URL pattern repositories contain placeholders like {name} or {version}
	return strings.Contains(url, "{") && strings.Contains(url, "}")
}

// isZipFile checks if the URL points to a ZIP file
func (ar *ArtifactResolver) isZipFile(url string) bool {
	return strings.HasSuffix(strings.ToLower(url), ".zip")
}

// discoverDirectoryArtifacts discovers artifacts from a directory-based repository
func (ar *ArtifactResolver) discoverDirectoryArtifacts(repo auth.ComposerRepository, packageName string) ([]*ArtifactInfo, error) {
	// For directory-based repositories, we need to list the directory contents
	// This would typically require HTTP directory listing or API support
	
	log.Printf("Directory-based artifact discovery not yet implemented for: %s", repo.URL)
	return nil, fmt.Errorf("directory-based artifact repositories not yet supported")
}

// discoverURLPatternArtifacts discovers artifacts using URL patterns
func (ar *ArtifactResolver) discoverURLPatternArtifacts(repo auth.ComposerRepository, packageName string) ([]*ArtifactInfo, error) {
	var artifacts []*ArtifactInfo

	// Common version patterns to try
	versionPatterns := []string{
		"1.0.0", "1.0", "latest", "master", "main",
		"2.0.0", "2.0", "0.1.0", "0.1",
	}

	urlPattern := repo.URL
	
	for _, version := range versionPatterns {
		// Replace placeholders in URL pattern
		artifactURL := strings.ReplaceAll(urlPattern, "{name}", packageName)
		artifactURL = strings.ReplaceAll(artifactURL, "{version}", version)
		
		// Replace vendor/package format
		if strings.Contains(packageName, "/") {
			parts := strings.Split(packageName, "/")
			if len(parts) == 2 {
				artifactURL = strings.ReplaceAll(artifactURL, "{vendor}", parts[0])
				artifactURL = strings.ReplaceAll(artifactURL, "{package}", parts[1])
			}
		}

		artifact := &ArtifactInfo{
			URL:        artifactURL,
			Name:       packageName,
			Version:    version,
			Downloaded: false,
		}

		// Check if this URL exists
		if ar.urlExists(artifactURL) {
			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}

// urlExists checks if a URL exists by making a HEAD request
func (ar *ArtifactResolver) urlExists(url string) bool {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	// Add authentication if available
	if err := ar.addAuthentication(req, url); err != nil {
		log.Printf("Warning: Failed to add authentication for %s: %v", url, err)
	}

	resp, err := ar.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// selectBestArtifact selects the best matching artifact based on version constraints
func (ar *ArtifactResolver) selectBestArtifact(artifacts []*ArtifactInfo, packageName, constraint string) (*ArtifactInfo, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}

	// Simple selection logic - can be enhanced with proper semver matching
	for _, artifact := range artifacts {
		if constraint == "" || constraint == "*" {
			return artifact, nil
		}

		if artifact.Version == constraint {
			return artifact, nil
		}

		// Check if constraint matches version pattern
		if ar.versionMatches(artifact.Version, constraint) {
			return artifact, nil
		}
	}

	// Return first artifact if no exact match
	return artifacts[0], nil
}

// versionMatches checks if a version matches a constraint (simplified)
func (ar *ArtifactResolver) versionMatches(version, constraint string) bool {
	// Simple matching logic - can be enhanced with proper semver
	if constraint == "*" || constraint == "" {
		return true
	}

	if strings.HasPrefix(constraint, "^") {
		// Caret range - match major version
		constraintVersion := strings.TrimPrefix(constraint, "^")
		return strings.HasPrefix(version, constraintVersion[:1])
	}

	if strings.HasPrefix(constraint, "~") {
		// Tilde range - match major.minor
		constraintVersion := strings.TrimPrefix(constraint, "~")
		parts := strings.Split(constraintVersion, ".")
		if len(parts) >= 2 {
			prefix := parts[0] + "." + parts[1]
			return strings.HasPrefix(version, prefix)
		}
	}

	return version == constraint
}

// downloadArtifact downloads and caches an artifact
func (ar *ArtifactResolver) downloadArtifact(repo auth.ComposerRepository, artifact *ArtifactInfo) error {
	log.Printf("Downloading artifact: %s", artifact.URL)

	// Create cache filename
	filename := ar.getCacheFilename(artifact)
	artifact.LocalPath = filepath.Join(ar.cacheDir, filename)

	// Check if already cached
	if _, err := os.Stat(artifact.LocalPath); err == nil {
		log.Printf("Artifact already cached: %s", artifact.LocalPath)
		artifact.Downloaded = true
		return nil
	}

	// Download the artifact
	req, err := http.NewRequest("GET", artifact.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication if available
	if err := ar.addAuthentication(req, artifact.URL); err != nil {
		return fmt.Errorf("failed to add authentication: %w", err)
	}

	resp, err := ar.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create output file
	outFile, err := os.Create(artifact.LocalPath)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer outFile.Close()

	// Copy downloaded content
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save artifact: %w", err)
	}

	artifact.Downloaded = true
	log.Printf("Artifact downloaded successfully: %s", artifact.LocalPath)
	return nil
}

// getCacheFilename generates a cache filename for an artifact
func (ar *ArtifactResolver) getCacheFilename(artifact *ArtifactInfo) string {
	// Sanitize name for filename
	name := sanitizeFilename(artifact.Name)
	version := sanitizeFilename(artifact.Version)
	
	if version != "" {
		return fmt.Sprintf("%s-%s.zip", name, version)
	}
	
	return fmt.Sprintf("%s.zip", name)
}

// extractPackageInfo extracts package information from a downloaded artifact
func (ar *ArtifactResolver) extractPackageInfo(artifact *ArtifactInfo) (*types.PackageInfo, error) {
	log.Printf("Extracting package info from: %s", artifact.LocalPath)

	// Create extraction directory
	extractDir := strings.TrimSuffix(artifact.LocalPath, ".zip")
	artifact.ExtractedDir = extractDir

	// Remove existing extraction directory
	os.RemoveAll(extractDir)

	// Extract ZIP file
	if err := ar.extractZipFile(artifact.LocalPath, extractDir); err != nil {
		return nil, fmt.Errorf("failed to extract ZIP: %w", err)
	}

	// Find composer.json in extracted files
	composerPath, err := ar.findComposerJSON(extractDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find composer.json: %w", err)
	}

	// Parse composer.json
	composerData, err := ar.parseComposerJSON(composerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	// Create package info
	packageInfo := &types.PackageInfo{
		Name:        composerData.Name,
		Version:     composerData.Version,
		Description: composerData.Description,
		Type:        composerData.Type,
		License:     ar.normalizeLicense(composerData.License),
		Authors:     ar.convertAuthors(composerData.Authors),
		Require:     composerData.Require,
		RequireDev:  composerData.RequireDev,
		Repository:  artifact.URL,
		IsPrivate:   false, // Will be set by caller if needed
	}

	return packageInfo, nil
}

// extractZipFile extracts a ZIP file to a directory
func (ar *ArtifactResolver) extractZipFile(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Create destination directory
	os.MkdirAll(destDir, 0755)

	// Extract files
	for _, file := range reader.File {
		path := filepath.Join(destDir, file.Name)

		// Security check: prevent zip slip attacks
		if !strings.HasPrefix(path, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path in ZIP: %s", file.Name)
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		// Create file
		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		// Create parent directory
		os.MkdirAll(filepath.Dir(path), 0755)

		// Create output file
		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer outFile.Close()

		_, err = io.Copy(outFile, fileReader)
		if err != nil {
			return err
		}
	}

	return nil
}

// findComposerJSON finds composer.json in extracted directory
func (ar *ArtifactResolver) findComposerJSON(baseDir string) (string, error) {
	var composerPath string

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == "composer.json" {
			composerPath = path
			return filepath.SkipDir // Stop after finding first composer.json
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	if composerPath == "" {
		return "", fmt.Errorf("composer.json not found in artifact")
	}

	return composerPath, nil
}

// parseComposerJSON parses a composer.json file
func (ar *ArtifactResolver) parseComposerJSON(filePath string) (*ComposerJSON, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.json: %w", err)
	}

	var composerData ComposerJSON
	if err := json.Unmarshal(content, &composerData); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	return &composerData, nil
}

// addAuthentication adds authentication headers to the request
func (ar *ArtifactResolver) addAuthentication(req *http.Request, artifactURL string) error {
	// Extract host from URL
	host := ar.extractHost(artifactURL)
	
	auth, hasAuth := ar.authManager.GetAuthForHost(host)
	if !hasAuth {
		return nil // No authentication needed
	}

	switch auth.Type {
	case "http-basic":
		req.SetBasicAuth(auth.Username, auth.Password)
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
	case "github-token":
		req.Header.Set("Authorization", fmt.Sprintf("token %s", auth.Token))
	case "gitlab-token":
		req.Header.Set("Private-Token", auth.Token)
	default:
		return fmt.Errorf("unsupported auth type: %s", auth.Type)
	}

	return nil
}

// extractHost extracts the host from a URL
func (ar *ArtifactResolver) extractHost(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Extract host part
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// normalizeLicense normalizes license information
func (ar *ArtifactResolver) normalizeLicense(license interface{}) []string {
	if license == nil {
		return []string{}
	}

	switch v := license.(type) {
	case string:
		if v == "" {
			return []string{}
		}
		return []string{v}
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

// convertAuthors converts author information
func (ar *ArtifactResolver) convertAuthors(authors []Author) []types.PackageAuthor {
	result := make([]types.PackageAuthor, len(authors))
	for i, author := range authors {
		result[i] = types.PackageAuthor{
			Name:     author.Name,
			Email:    author.Email,
			Homepage: "", // Not available in basic Author struct
			Role:     author.Role,
		}
	}
	return result
}

// sanitizeFilename sanitizes a string for use as a filename
func sanitizeFilename(name string) string {
	// Replace invalid characters for filenames
	reg := regexp.MustCompile(`[<>:"/\\|?*]`)
	name = reg.ReplaceAllString(name, "_")
	
	// Replace slashes with hyphens for vendor/package format
	name = strings.ReplaceAll(name, "/", "-")
	
	return name
}

// Cleanup removes temporary directories and files created by the artifact resolver
func (ar *ArtifactResolver) Cleanup() {
	if ar.cacheDir != "" {
		os.RemoveAll(ar.cacheDir)
	}
}