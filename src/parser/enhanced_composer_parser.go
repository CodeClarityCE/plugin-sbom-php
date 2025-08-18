package parser

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeClarityCE/plugin-php-sbom/src/artifact"
	"github.com/CodeClarityCE/plugin-php-sbom/src/auth"
	"github.com/CodeClarityCE/plugin-php-sbom/src/resolver"
	"github.com/CodeClarityCE/plugin-php-sbom/src/vcs"
)

// EnhancedComposerJSON extends ComposerJSON with repository information
type EnhancedComposerJSON struct {
	*ComposerJSON
	Repositories []auth.ComposerRepository `json:"repositories,omitempty"`
	Config       map[string]any    `json:"config,omitempty"`
}

// EnhancedPackageInfo extends PackageInfo with private repository metadata
type EnhancedPackageInfo struct {
	*PackageInfo
	IsPrivate          bool   `json:"is_private,omitempty"`
	SourceRepository   string `json:"source_repository,omitempty"`
	RepositoryType     string `json:"repository_type,omitempty"`
	AuthenticationUsed bool   `json:"authentication_used,omitempty"`
}

// EnhancedSBOM represents an SBOM with private repository information
type EnhancedSBOM struct {
	Packages            []EnhancedPackageInfo     `json:"packages"`
	DevPackages         []EnhancedPackageInfo     `json:"dev_packages"`
	PrivateRepositories []auth.ComposerRepository `json:"private_repositories"`
	AuthenticationInfo  []AuthInfo                `json:"authentication_info"`
	ResolutionErrors    []ResolutionError         `json:"resolution_errors"`
}

// AuthInfo represents authentication information used during resolution
type AuthInfo struct {
	Host       string        `json:"host"`
	AuthType   auth.AuthType `json:"auth_type"`
	Success    bool          `json:"success"`
	Repository string        `json:"repository"`
}

// ResolutionError represents an error that occurred during package resolution
type ResolutionError struct {
	PackageName string `json:"package_name"`
	Repository  string `json:"repository"`
	Error       string `json:"error"`
	AuthFailed  bool   `json:"auth_failed"`
}

// EnhancedComposerParser provides enhanced parsing with private repository support
type EnhancedComposerParser struct {
	authManager     *auth.AuthManager
	packageResolver *resolver.PrivatePackageResolver
	projectDir      string
}

// NewEnhancedComposerParser creates a new enhanced composer parser
func NewEnhancedComposerParser(projectDir string) (*EnhancedComposerParser, error) {
	authManager := auth.NewAuthManager()
	packageResolver := resolver.NewPrivatePackageResolver(authManager)
	
	// Create and set up Git resolver
	gitResolver := vcs.NewGitResolver(authManager)
	packageResolver.SetGitResolver(gitResolver)
	
	// Create and set up Artifact resolver
	artifactResolver := artifact.NewArtifactResolver(authManager)
	packageResolver.SetArtifactResolver(artifactResolver)

	parser := &EnhancedComposerParser{
		authManager:     authManager,
		packageResolver: packageResolver,
		projectDir:      projectDir,
	}

	// Load authentication and repository configuration
	if err := parser.loadConfiguration(); err != nil {
		log.Printf("Warning: Failed to load complete configuration: %v", err)
		// Don't fail completely, continue with partial configuration
	}

	return parser, nil
}

// loadConfiguration loads authentication and repository configuration
func (p *EnhancedComposerParser) loadConfiguration() error {
	var errors []string

	// Load repository configuration from composer.json
	composerJSONPath := filepath.Join(p.projectDir, "composer.json")
	if err := p.authManager.LoadFromComposerJSON(composerJSONPath); err != nil {
		errors = append(errors, fmt.Sprintf("composer.json: %v", err))
	}

	// Load authentication from auth.json
	if err := p.authManager.LoadFromAuthJSON(p.projectDir); err != nil {
		errors = append(errors, fmt.Sprintf("auth.json: %v", err))
	}

	// Load authentication from environment variables
	if err := p.authManager.LoadFromEnvironment(); err != nil {
		errors = append(errors, fmt.Sprintf("environment: %v", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration loading errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// ParseWithPrivateRepos parses composer files with private repository support
func (p *EnhancedComposerParser) ParseWithPrivateRepos() (*EnhancedSBOM, error) {
	log.Printf("Starting enhanced parsing with private repository support")

	// Parse standard composer files
	composerJSONPath := filepath.Join(p.projectDir, "composer.json")
	composerLockPath := filepath.Join(p.projectDir, "composer.lock")

	_, err := p.parseEnhancedComposerJSON(composerJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	composerLock, err := ParseComposerLock(composerLockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composer.lock: %w", err)
	}

	// Create enhanced SBOM
	sbom := &EnhancedSBOM{
		Packages:            []EnhancedPackageInfo{},
		DevPackages:         []EnhancedPackageInfo{},
		PrivateRepositories: p.getPrivateRepositories(),
		AuthenticationInfo:  []AuthInfo{},
		ResolutionErrors:    []ResolutionError{},
	}

	// Process regular packages
	for _, pkg := range composerLock.Packages {
		enhancedPkg, authInfo, resolutionErr := p.enhancePackageInfo(pkg)
		sbom.Packages = append(sbom.Packages, enhancedPkg)

		if authInfo != nil {
			sbom.AuthenticationInfo = append(sbom.AuthenticationInfo, *authInfo)
		}
		if resolutionErr != nil {
			sbom.ResolutionErrors = append(sbom.ResolutionErrors, *resolutionErr)
		}
	}

	// Process dev packages
	for _, pkg := range composerLock.PackagesDev {
		enhancedPkg, authInfo, resolutionErr := p.enhancePackageInfo(pkg)
		sbom.DevPackages = append(sbom.DevPackages, enhancedPkg)

		if authInfo != nil {
			sbom.AuthenticationInfo = append(sbom.AuthenticationInfo, *authInfo)
		}
		if resolutionErr != nil {
			sbom.ResolutionErrors = append(sbom.ResolutionErrors, *resolutionErr)
		}
	}

	log.Printf("Enhanced parsing completed: %d packages, %d dev packages, %d private repos",
		len(sbom.Packages), len(sbom.DevPackages), len(sbom.PrivateRepositories))

	return sbom, nil
}

// parseEnhancedComposerJSON parses composer.json with repository information
func (p *EnhancedComposerParser) parseEnhancedComposerJSON(filePath string) (*EnhancedComposerJSON, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.json: %w", err)
	}

	var enhancedJSON EnhancedComposerJSON
	if err := json.Unmarshal(data, &enhancedJSON); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	// Also parse the basic structure
	var basicJSON ComposerJSON
	if err := json.Unmarshal(data, &basicJSON); err != nil {
		return nil, fmt.Errorf("failed to parse basic composer.json: %w", err)
	}

	enhancedJSON.ComposerJSON = &basicJSON
	return &enhancedJSON, nil
}

// enhancePackageInfo enhances package information with private repository metadata
func (p *EnhancedComposerParser) enhancePackageInfo(pkg PackageInfo) (EnhancedPackageInfo, *AuthInfo, *ResolutionError) {
	enhanced := EnhancedPackageInfo{
		PackageInfo: &pkg,
		IsPrivate:   false,
	}

	// Try to resolve additional metadata from private repositories
	packageInfo, err := p.packageResolver.ResolvePackage(pkg.Name, pkg.Version)
	if err != nil {
		resolutionErr := &ResolutionError{
			PackageName: pkg.Name,
			Error:       err.Error(),
			AuthFailed:  p.isAuthenticationError(err),
		}

		// Try to determine repository from package source
		if pkg.Source.URL != "" {
			resolutionErr.Repository = pkg.Source.URL
			enhanced.SourceRepository = pkg.Source.URL
		}

		return enhanced, nil, resolutionErr
	}

	// Enhance with resolved information
	if packageInfo != nil {
		enhanced.IsPrivate = packageInfo.IsPrivate
		enhanced.SourceRepository = packageInfo.Repository
		enhanced.AuthenticationUsed = p.wasAuthenticationUsed(packageInfo.Repository)

		// Determine repository type
		enhanced.RepositoryType = p.getRepositoryType(packageInfo.Repository)

		// Create auth info if authentication was used
		var authInfo *AuthInfo
		if enhanced.AuthenticationUsed {
			authInfo = &AuthInfo{
				Host:       p.extractHost(packageInfo.Repository),
				Repository: packageInfo.Repository,
				Success:    true,
			}

			if auth, hasAuth := p.authManager.GetAuthForHost(authInfo.Host); hasAuth {
				authInfo.AuthType = auth.Type
			}
		}

		return enhanced, authInfo, nil
	}

	return enhanced, nil, nil
}

// getPrivateRepositories returns all private repositories from configuration
func (p *EnhancedComposerParser) getPrivateRepositories() []auth.ComposerRepository {
	var privateRepos []auth.ComposerRepository

	for _, repo := range p.authManager.GetRepositories() {
		if p.authManager.IsPrivateRepository(repo) {
			privateRepos = append(privateRepos, repo)
		}
	}

	return privateRepos
}

// isAuthenticationError checks if an error is related to authentication
func (p *EnhancedComposerParser) isAuthenticationError(err error) bool {
	errorStr := strings.ToLower(err.Error())
	authErrors := []string{
		"401",
		"403",
		"unauthorized",
		"forbidden",
		"authentication",
		"credential",
		"token",
	}

	for _, authError := range authErrors {
		if strings.Contains(errorStr, authError) {
			return true
		}
	}

	return false
}

// wasAuthenticationUsed checks if authentication was used for a repository
func (p *EnhancedComposerParser) wasAuthenticationUsed(repoURL string) bool {
	if repoURL == "" {
		return false
	}

	host := p.extractHost(repoURL)
	_, hasAuth := p.authManager.GetAuthForHost(host)
	return hasAuth
}

// getRepositoryType determines the repository type from URL
func (p *EnhancedComposerParser) getRepositoryType(repoURL string) string {
	if repoURL == "" {
		return "unknown"
	}

	repoURL = strings.ToLower(repoURL)

	if strings.Contains(repoURL, "packagist") {
		return "packagist"
	}
	if strings.Contains(repoURL, "github") {
		return "github"
	}
	if strings.Contains(repoURL, "gitlab") {
		return "gitlab"
	}
	if strings.Contains(repoURL, "bitbucket") {
		return "bitbucket"
	}
	if strings.Contains(repoURL, ".git") {
		return "git"
	}

	return "composer"
}

// extractHost extracts the host from a repository URL
func (p *EnhancedComposerParser) extractHost(repoURL string) string {
	// Remove protocol
	url := strings.TrimPrefix(repoURL, "https://")
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

// GetPrivatePackageCount returns the count of private packages
func (sbom *EnhancedSBOM) GetPrivatePackageCount() int {
	count := 0

	for _, pkg := range sbom.Packages {
		if pkg.IsPrivate {
			count++
		}
	}

	for _, pkg := range sbom.DevPackages {
		if pkg.IsPrivate {
			count++
		}
	}

	return count
}

// GetAuthenticationSummary returns a summary of authentication usage
func (sbom *EnhancedSBOM) GetAuthenticationSummary() map[string]int {
	summary := make(map[string]int)

	for _, authInfo := range sbom.AuthenticationInfo {
		authTypeStr := string(authInfo.AuthType)
		if authInfo.Success {
			summary[authTypeStr+"_success"]++
		} else {
			summary[authTypeStr+"_failure"]++
		}
	}

	return summary
}

// GetResolutionErrorSummary returns a summary of resolution errors
func (sbom *EnhancedSBOM) GetResolutionErrorSummary() map[string]int {
	summary := map[string]int{
		"total_errors":   len(sbom.ResolutionErrors),
		"auth_failures":  0,
		"network_errors": 0,
		"not_found":      0,
		"other_errors":   0,
	}

	for _, err := range sbom.ResolutionErrors {
		if err.AuthFailed {
			summary["auth_failures"]++
		} else if strings.Contains(strings.ToLower(err.Error), "network") ||
			strings.Contains(strings.ToLower(err.Error), "timeout") {
			summary["network_errors"]++
		} else if strings.Contains(strings.ToLower(err.Error), "not found") ||
			strings.Contains(strings.ToLower(err.Error), "404") {
			summary["not_found"]++
		} else {
			summary["other_errors"]++
		}
	}

	return summary
}
