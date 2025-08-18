package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeClarityCE/plugin-php-sbom/src/auth"
	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
)

// PackageInfo is an alias for the shared types.PackageInfo
type PackageInfo = types.PackageInfo

// PackageAuthor is an alias for the shared types.PackageAuthor  
type PackageAuthor = types.PackageAuthor

// PackageCache represents a simple in-memory cache for package metadata
type PackageCache struct {
	cache   map[string]*CacheEntry
	ttl     time.Duration
	maxSize int
}

// CacheEntry represents a cached package entry
type CacheEntry struct {
	data      *PackageInfo
	timestamp time.Time
}

// NewPackageCache creates a new package cache
func NewPackageCache(ttl time.Duration, maxSize int) *PackageCache {
	return &PackageCache{
		cache:   make(map[string]*CacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Get retrieves a package from cache if it exists and is not expired
func (c *PackageCache) Get(key string) (*PackageInfo, bool) {
	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	if time.Since(entry.timestamp) > c.ttl {
		delete(c.cache, key)
		return nil, false
	}

	return entry.data, true
}

// Set stores a package in cache
func (c *PackageCache) Set(key string, data *PackageInfo) {
	// Simple LRU eviction if cache is full
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[key] = &CacheEntry{
		data:      data,
		timestamp: time.Now(),
	}
}

// evictOldest removes the oldest entry from cache
func (c *PackageCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.cache {
		if oldestKey == "" || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// GitResolver interface to avoid circular dependency
type GitResolver interface {
	ResolveGitRepository(repo auth.ComposerRepository, packageName, constraint string) (*PackageInfo, error)
}

// ArtifactResolver interface to avoid circular dependency
type ArtifactResolver interface {
	ResolveArtifactRepository(repo auth.ComposerRepository, packageName, constraint string) (*PackageInfo, error)
}

// PrivatePackageResolver resolves package metadata from private repositories
type PrivatePackageResolver struct {
	authManager      *auth.AuthManager
	httpClient       *http.Client
	cache            *PackageCache
	gitResolver      GitResolver
	artifactResolver ArtifactResolver
}

// NewPrivatePackageResolver creates a new private package resolver
func NewPrivatePackageResolver(authManager *auth.AuthManager) *PrivatePackageResolver {
	return &PrivatePackageResolver{
		authManager: authManager,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: false,
			},
		},
		cache:            NewPackageCache(1*time.Hour, 1000), // 1 hour TTL, max 1000 entries
		gitResolver:      nil, // Will be set externally to avoid circular dependency
		artifactResolver: nil, // Will be set externally to avoid circular dependency
	}
}

// SetGitResolver sets the Git resolver to avoid circular dependency
func (r *PrivatePackageResolver) SetGitResolver(gitResolver GitResolver) {
	r.gitResolver = gitResolver
}

// SetArtifactResolver sets the Artifact resolver to avoid circular dependency
func (r *PrivatePackageResolver) SetArtifactResolver(artifactResolver ArtifactResolver) {
	r.artifactResolver = artifactResolver
}

// ResolvePackage resolves package metadata from public and private repositories
func (r *PrivatePackageResolver) ResolvePackage(name, constraint string) (*PackageInfo, error) {
	cacheKey := fmt.Sprintf("%s@%s", name, constraint)

	// Check cache first
	if cached, found := r.cache.Get(cacheKey); found {
		log.Printf("Cache hit for package: %s", name)
		return cached, nil
	}

	log.Printf("Resolving package: %s with constraint: %s", name, constraint)

	// Try to resolve from repositories in order
	repositories := r.authManager.GetRepositories()

	for _, repo := range repositories {
		if r.shouldSkipRepository(repo, name) {
			continue
		}

		packageInfo, err := r.resolveFromRepository(repo, name, constraint)
		if err != nil {
			log.Printf("Failed to resolve %s from repository %s: %v", name, repo.URL, err)
			continue
		}

		if packageInfo != nil {
			// Mark as private if it came from a private repository
			packageInfo.IsPrivate = r.authManager.IsPrivateRepository(repo)
			packageInfo.Repository = repo.URL

			// Cache the result
			r.cache.Set(cacheKey, packageInfo)

			log.Printf("Resolved package %s from repository: %s", name, repo.URL)
			return packageInfo, nil
		}
	}

	// If not found in private repositories, try public repositories
	// (This would normally query packagist.org or other public sources)
	publicInfo, err := r.resolveFromPublicRepository(name, constraint)
	if err == nil && publicInfo != nil {
		r.cache.Set(cacheKey, publicInfo)
		return publicInfo, nil
	}

	return nil, fmt.Errorf("package %s not found in any repository", name)
}

// shouldSkipRepository checks if a repository should be skipped for a given package
func (r *PrivatePackageResolver) shouldSkipRepository(repo auth.ComposerRepository, packageName string) bool {
	// Check "only" filter
	if len(repo.Only) > 0 {
		for _, pattern := range repo.Only {
			if r.matchesPattern(packageName, pattern) {
				return false // Include this package
			}
		}
		return true // Package not in "only" list, skip
	}

	// Check "exclude" filter
	if len(repo.Exclude) > 0 {
		for _, pattern := range repo.Exclude {
			if r.matchesPattern(packageName, pattern) {
				return true // Package is excluded, skip
			}
		}
	}

	return false // Don't skip
}

// matchesPattern checks if a package name matches a pattern (simple wildcard support)
func (r *PrivatePackageResolver) matchesPattern(packageName, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if strings.Contains(pattern, "*") {
		// Simple wildcard matching
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			return strings.HasPrefix(packageName, prefix)
		}
		if suffix, found := strings.CutPrefix(pattern, "*"); found {
			return strings.HasSuffix(packageName, suffix)
		}
	}

	return packageName == pattern
}

// resolveFromRepository resolves a package from a specific repository
func (r *PrivatePackageResolver) resolveFromRepository(repo auth.ComposerRepository, name, constraint string) (*PackageInfo, error) {
	switch repoType := repo.Type; repoType {
	case "composer":
		return r.resolveFromComposerRepository(repo, name, constraint)
	case "vcs":
		return r.resolveFromVCSRepository(repo, name, constraint)
	case "artifact":
		return r.resolveFromArtifactRepository(repo, name, constraint)
	case "path":
		return r.resolveFromPathRepository(repo, name, constraint)
	default:
		return nil, fmt.Errorf("unsupported repository type: %s", repo.Type)
	}
}

// resolveFromComposerRepository resolves from a Composer-type repository (Packagist-compatible)
func (r *PrivatePackageResolver) resolveFromComposerRepository(repo auth.ComposerRepository, name, constraint string) (*PackageInfo, error) {
	// Build the API URL for the package
	baseURL := strings.TrimSuffix(repo.URL, "/")
	apiURL := fmt.Sprintf("%s/packages/%s.json", baseURL, name)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication if available
	if err := r.addAuthentication(req, repo.URL); err != nil {
		return nil, fmt.Errorf("failed to add authentication: %w", err)
	}

	// Add custom headers from repository options
	r.addCustomHeaders(req, repo.Options)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // Package not found in this repository
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the Packagist-style response
	var packageData struct {
		Packages map[string]map[string]PackageInfo `json:"packages"`
	}

	if err := json.Unmarshal(body, &packageData); err != nil {
		return nil, fmt.Errorf("failed to parse package data: %w", err)
	}

	// Find the best matching version
	if packages, exists := packageData.Packages[name]; exists {
		return r.findBestVersion(packages, constraint)
	}

	return nil, nil // Package not found
}

// resolveFromVCSRepository resolves from a VCS repository (Git, SVN, etc.)
func (r *PrivatePackageResolver) resolveFromVCSRepository(repo auth.ComposerRepository, name, constraint string) (*PackageInfo, error) {
	log.Printf("Resolving VCS repository: %s for package: %s", repo.URL, name)
	
	// Use GitResolver for Git-based VCS repositories if available
	if r.gitResolver != nil {
		return r.gitResolver.ResolveGitRepository(repo, name, constraint)
	}
	
	log.Printf("VCS repository resolution not available - GitResolver not set")
	return nil, nil
}

// resolveFromArtifactRepository resolves from an artifact repository
func (r *PrivatePackageResolver) resolveFromArtifactRepository(repo auth.ComposerRepository, name, constraint string) (*PackageInfo, error) {
	log.Printf("Resolving artifact repository: %s for package: %s", repo.URL, name)
	
	// Use ArtifactResolver if available
	if r.artifactResolver != nil {
		return r.artifactResolver.ResolveArtifactRepository(repo, name, constraint)
	}
	
	log.Printf("Artifact repository resolution not available - ArtifactResolver not set")
	return nil, nil
}

// resolveFromPathRepository resolves from a local path repository
func (r *PrivatePackageResolver) resolveFromPathRepository(repo auth.ComposerRepository, name, constraint string) (*PackageInfo, error) {
	// Path resolution would require local filesystem access
	log.Printf("Path repository resolution not yet implemented for: %s", repo.URL)
	return nil, nil
}

// resolveFromPublicRepository resolves from public repositories (fallback)
func (r *PrivatePackageResolver) resolveFromPublicRepository(name, constraint string) (*PackageInfo, error) {
	// This would typically query packagist.org
	// For now, return a placeholder
	log.Printf("Public repository resolution not yet implemented for: %s", name)
	return nil, nil
}

// addAuthentication adds authentication headers to the request
func (r *PrivatePackageResolver) addAuthentication(req *http.Request, repoURL string) error {
	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return err
	}

	auth, hasAuth := r.authManager.GetAuthForHost(parsedURL.Host)
	if !hasAuth {
		return nil // No authentication needed
	}

	switch authType := auth.Type; authType {
	case "http-basic":
		req.SetBasicAuth(auth.Username, auth.Password)
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
	case "github-token":
		req.Header.Set("Authorization", fmt.Sprintf("token %s", auth.Token))
	case "gitlab-token":
		req.Header.Set("Private-Token", auth.Token)
	case "github-oauth":
		req.Header.Set("Authorization", fmt.Sprintf("token %s", auth.Token))
	default:
		return fmt.Errorf("unsupported auth type: %s", auth.Type)
	}

	return nil
}

// addCustomHeaders adds custom headers from repository options
func (r *PrivatePackageResolver) addCustomHeaders(req *http.Request, options map[string]any) {
	if options == nil {
		return
	}

	if httpOptions, exists := options["http"]; exists {
		if httpMap, ok := httpOptions.(map[string]any); ok {
			if headers, exists := httpMap["header"]; exists {
				if headerList, ok := headers.([]any); ok {
					for _, header := range headerList {
						if headerStr, ok := header.(string); ok {
							parts := strings.SplitN(headerStr, ":", 2)
							if len(parts) == 2 {
								req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
							}
						}
					}
				}
			}
		}
	}
}

// findBestVersion finds the best matching version for a constraint
func (r *PrivatePackageResolver) findBestVersion(packages map[string]PackageInfo, constraint string) (*PackageInfo, error) {
	// Simple version matching - in production this should use proper semver
	if constraint == "*" || constraint == "" {
		// Return the latest version (simplified - would need proper version sorting)
		for _, pkg := range packages {
			return &pkg, nil
		}
	}

	// Look for exact version match
	if pkg, exists := packages[constraint]; exists {
		return &pkg, nil
	}

	// Return the first available version as fallback
	for _, pkg := range packages {
		return &pkg, nil
	}

	return nil, fmt.Errorf("no matching version found for constraint: %s", constraint)
}

// GetRepositories returns all configured repositories
func (r *PrivatePackageResolver) GetRepositories() []auth.ComposerRepository {
	return r.authManager.GetRepositories()
}

// IsPackagePrivate checks if a package is from a private repository
func (r *PrivatePackageResolver) IsPackagePrivate(packageName string) (bool, error) {
	cacheKey := fmt.Sprintf("private:%s", packageName)

	if cached, found := r.cache.Get(cacheKey); found {
		return cached.IsPrivate, nil
	}

	// Try to resolve the package to determine if it's private
	packageInfo, err := r.ResolvePackage(packageName, "*")
	if err != nil {
		return false, err
	}

	return packageInfo != nil && packageInfo.IsPrivate, nil
}
