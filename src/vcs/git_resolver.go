package vcs

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeClarityCE/plugin-php-sbom/src/auth"
	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
)

// GitResolver handles Git-based VCS repositories
type GitResolver struct {
	authManager *auth.AuthManager
	httpClient  *http.Client
	tempDir     string
}

// ComposerJSON represents basic composer.json structure for VCS resolution
type ComposerJSON struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	License     any                    `json:"license"`
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

// GitPackageInfo represents package information from a Git repository
type GitPackageInfo struct {
	*types.PackageInfo
	GitURL       string `json:"git_url"`
	Branch       string `json:"branch"`
	Tag          string `json:"tag"`
	Commit       string `json:"commit"`
	LastModified string `json:"last_modified"`
}

// NewGitResolver creates a new Git repository resolver
func NewGitResolver(authManager *auth.AuthManager) *GitResolver {
	tempDir := filepath.Join(os.TempDir(), "php-sbom-git-cache")
	os.MkdirAll(tempDir, 0755)

	return &GitResolver{
		authManager: authManager,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		tempDir: tempDir,
	}
}

// ResolveGitRepository resolves package information from a Git repository
func (gr *GitResolver) ResolveGitRepository(repo auth.ComposerRepository, packageName, constraint string) (*types.PackageInfo, error) {
	log.Printf("Resolving package %s from Git repository: %s", packageName, repo.URL)

	// Parse Git repository URL
	gitInfo, err := gr.parseGitURL(repo.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Git URL: %w", err)
	}

	// Check if this is a GitHub/GitLab API accessible repository
	if gr.isAPIAccessible(gitInfo) {
		packageInfo, err := gr.resolveViaAPI(gitInfo, packageName, constraint)
		if err == nil && packageInfo != nil {
			return packageInfo, nil
		}
		log.Printf("API resolution failed, falling back to Git clone: %v", err)
	}

	// Fallback to Git clone method
	return gr.resolveViaGitClone(gitInfo, packageName, constraint)
}

// GitRepositoryInfo represents parsed Git repository information
type GitRepositoryInfo struct {
	URL         string
	Host        string
	Owner       string
	Repository  string
	Branch      string
	Tag         string
	Commit      string
	IsGitHub    bool
	IsGitLab    bool
	IsPrivate   bool
}

// parseGitURL parses a Git repository URL and extracts relevant information
func (gr *GitResolver) parseGitURL(gitURL string) (*GitRepositoryInfo, error) {
	// Normalize the URL
	gitURL = strings.TrimSuffix(gitURL, ".git")
	gitURL = strings.TrimSuffix(gitURL, "/")

	// Parse URL
	u, err := url.Parse(gitURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Git URL: %w", err)
	}

	info := &GitRepositoryInfo{
		URL:  gitURL,
		Host: u.Host,
	}

	// Check if it's GitHub or GitLab
	switch host := u.Host; {
	case strings.Contains(host, "github"):
		info.IsGitHub = true
	case strings.Contains(host, "gitlab"):
		info.IsGitLab = true
	}

	// Extract owner and repository from path
	pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(pathParts) >= 2 {
		info.Owner = pathParts[0]
		info.Repository = pathParts[1]
	}

	// Check if repository appears to be private
	info.IsPrivate = gr.isPrivateRepository(u.Host)

	return info, nil
}

// isAPIAccessible checks if the repository can be accessed via API
func (gr *GitResolver) isAPIAccessible(gitInfo *GitRepositoryInfo) bool {
	return (gitInfo.IsGitHub || gitInfo.IsGitLab) && gitInfo.Owner != "" && gitInfo.Repository != ""
}

// isPrivateRepository checks if a repository host indicates a private repository
func (gr *GitResolver) isPrivateRepository(host string) bool {
	privateIndicators := []string{
		"company.com",
		"corp.com",
		"internal",
		"private",
		"enterprise",
	}

	hostLower := strings.ToLower(host)
	for _, indicator := range privateIndicators {
		if strings.Contains(hostLower, indicator) {
			return true
		}
	}

	// If it's not github.com or gitlab.com, assume it might be private
	return !strings.Contains(hostLower, "github.com") && !strings.Contains(hostLower, "gitlab.com")
}

// resolveViaAPI attempts to resolve package information via GitHub/GitLab API
func (gr *GitResolver) resolveViaAPI(gitInfo *GitRepositoryInfo, packageName, constraint string) (*types.PackageInfo, error) {
	if gitInfo.IsGitHub {
		return gr.resolveViaGitHubAPI(gitInfo, packageName, constraint)
	} else if gitInfo.IsGitLab {
		return gr.resolveViaGitLabAPI(gitInfo, packageName, constraint)
	}

	return nil, fmt.Errorf("API not supported for this repository type")
}

// resolveViaGitHubAPI resolves package information via GitHub API
func (gr *GitResolver) resolveViaGitHubAPI(gitInfo *GitRepositoryInfo, packageName, constraint string) (*types.PackageInfo, error) {
	// First, try to get composer.json from the repository
	composerURL := fmt.Sprintf("https://api.%s/repos/%s/%s/contents/composer.json",
		strings.Replace(gitInfo.Host, "github.", "github.com", 1), gitInfo.Owner, gitInfo.Repository)

	req, err := http.NewRequest("GET", composerURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication if available
	if err := gr.addGitHubAuthentication(req, gitInfo.Host); err != nil {
		log.Printf("Warning: Failed to add GitHub authentication: %v", err)
	}

	resp, err := gr.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch composer.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("composer.json not found in repository")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	// Parse GitHub API response
	var githubResponse struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&githubResponse); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub API response: %w", err)
	}

	// Decode base64 content
	composerContent, err := decodeBase64Content(githubResponse.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode composer.json content: %w", err)
	}

	// Parse composer.json
	var composerData ComposerJSON
	if err := json.Unmarshal(composerContent, &composerData); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	// Check if this is the package we're looking for
	if composerData.Name != packageName {
		return nil, fmt.Errorf("package name mismatch: expected %s, got %s", packageName, composerData.Name)
	}

	// Get repository information for version/commit details
	repoInfo, err := gr.getGitHubRepositoryInfo(gitInfo)
	if err != nil {
		log.Printf("Warning: Could not get repository info: %v", err)
	}

	// Create package info
	packageInfo := &types.PackageInfo{
		Name:        composerData.Name,
		Version:     gr.determineVersionFromConstraint(constraint, repoInfo),
		Description: composerData.Description,
		Type:        composerData.Type,
		Keywords:    []string{}, // Keywords not available in this context
		Homepage:    "",         // Homepage not available in this context
		License:     gr.normalizeLicense(composerData.License),
		Authors:     gr.convertAuthors(composerData.Authors),
		Require:     composerData.Require,
		RequireDev:  composerData.RequireDev,
		Repository:  gitInfo.URL,
		IsPrivate:   gitInfo.IsPrivate,
	}

	return packageInfo, nil
}

// resolveViaGitLabAPI resolves package information via GitLab API
func (gr *GitResolver) resolveViaGitLabAPI(gitInfo *GitRepositoryInfo, packageName, constraint string) (*types.PackageInfo, error) {
	// GitLab API implementation
	projectPath := fmt.Sprintf("%s/%s", gitInfo.Owner, gitInfo.Repository)
	encodedPath := url.QueryEscape(projectPath)
	
	composerURL := fmt.Sprintf("https://%s/api/v4/projects/%s/repository/files/composer.json/raw?ref=main",
		gitInfo.Host, encodedPath)

	req, err := http.NewRequest("GET", composerURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication if available
	if err := gr.addGitLabAuthentication(req, gitInfo.Host); err != nil {
		log.Printf("Warning: Failed to add GitLab authentication: %v", err)
	}

	resp, err := gr.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch composer.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Try master branch as fallback
		composerURL = strings.Replace(composerURL, "ref=main", "ref=master", 1)
		req, _ = http.NewRequest("GET", composerURL, nil)
		gr.addGitLabAuthentication(req, gitInfo.Host)
		
		resp, err = gr.httpClient.Do(req)
		if err != nil || resp.StatusCode == 404 {
			return nil, fmt.Errorf("composer.json not found in repository")
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitLab API returned status %d", resp.StatusCode)
	}

	// Read composer.json content directly
	composerContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.json content: %w", err)
	}

	// Parse composer.json
	var composerData ComposerJSON
	if err := json.Unmarshal(composerContent, &composerData); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	// Check if this is the package we're looking for
	if composerData.Name != packageName {
		return nil, fmt.Errorf("package name mismatch: expected %s, got %s", packageName, composerData.Name)
	}

	// Create package info
	packageInfo := &types.PackageInfo{
		Name:        composerData.Name,
		Version:     gr.determineVersionFromConstraint(constraint, nil),
		Description: composerData.Description,
		Type:        composerData.Type,
		Keywords:    []string{}, // Keywords not available in this context
		Homepage:    "",         // Homepage not available in this context
		License:     gr.normalizeLicense(composerData.License),
		Authors:     gr.convertAuthors(composerData.Authors),
		Require:     composerData.Require,
		RequireDev:  composerData.RequireDev,
		Repository:  gitInfo.URL,
		IsPrivate:   gitInfo.IsPrivate,
	}

	return packageInfo, nil
}

// resolveViaGitClone resolves package information by cloning the repository
func (gr *GitResolver) resolveViaGitClone(gitInfo *GitRepositoryInfo, packageName, constraint string) (*types.PackageInfo, error) {
	// Create temporary directory for this repository
	repoDir := filepath.Join(gr.tempDir, sanitizeForFilename(gitInfo.Repository))
	
	// Remove existing directory if it exists
	os.RemoveAll(repoDir)

	// Clone the repository
	if err := gr.cloneRepository(gitInfo, repoDir); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Ensure cleanup
	defer os.RemoveAll(repoDir)

	// Read composer.json from cloned repository
	composerPath := filepath.Join(repoDir, "composer.json")
	if _, err := os.Stat(composerPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("composer.json not found in repository")
	}

	// Read and parse composer.json
	content, err := os.ReadFile(composerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.json: %w", err)
	}

	var composerData ComposerJSON
	if err := json.Unmarshal(content, &composerData); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	// Check if this is the package we're looking for
	if composerData.Name != packageName {
		return nil, fmt.Errorf("package name mismatch: expected %s, got %s", packageName, composerData.Name)
	}

	// Get current commit information
	commitInfo, err := gr.getCurrentCommitInfo(repoDir)
	if err != nil {
		log.Printf("Warning: Could not get commit info: %v", err)
	}

	// Create package info
	packageInfo := &types.PackageInfo{
		Name:        composerData.Name,
		Version:     gr.determineVersionFromConstraint(constraint, commitInfo),
		Description: composerData.Description,
		Type:        composerData.Type,
		Keywords:    []string{}, // Keywords not available in this context
		Homepage:    "",         // Homepage not available in this context
		License:     gr.normalizeLicense(composerData.License),
		Authors:     gr.convertAuthors(composerData.Authors),
		Require:     composerData.Require,
		RequireDev:  composerData.RequireDev,
		Repository:  gitInfo.URL,
		IsPrivate:   gitInfo.IsPrivate,
	}

	return packageInfo, nil
}

// Helper functions

func (gr *GitResolver) addGitHubAuthentication(req *http.Request, host string) error {
	auth, hasAuth := gr.authManager.GetAuthForHost(host)
	if !hasAuth {
		return nil
	}

	switch authType := auth.Type; authType {
	case "github-oauth", "github-token":
		req.Header.Set("Authorization", fmt.Sprintf("token %s", auth.Token))
	case "http-basic":
		req.SetBasicAuth(auth.Username, auth.Password)
	}

	return nil
}

func (gr *GitResolver) addGitLabAuthentication(req *http.Request, host string) error {
	auth, hasAuth := gr.authManager.GetAuthForHost(host)
	if !hasAuth {
		return nil
	}

	switch authType := auth.Type; authType {
	case "gitlab-token":
		req.Header.Set("Private-Token", auth.Token)
	case "http-basic":
		req.SetBasicAuth(auth.Username, auth.Password)
	}

	return nil
}

func (gr *GitResolver) cloneRepository(gitInfo *GitRepositoryInfo, targetDir string) error {
	// Prepare Git clone command
	gitURL := gitInfo.URL
	if !strings.HasSuffix(gitURL, ".git") {
		gitURL += ".git"
	}

	// Basic clone command
	cmd := exec.Command("git", "clone", "--depth=1", gitURL, targetDir)

	// Set up authentication if needed
	if gitInfo.IsPrivate {
		if err := gr.setupGitAuthentication(cmd, gitInfo); err != nil {
			return fmt.Errorf("failed to setup Git authentication: %w", err)
		}
	}

	// Execute clone
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
	}

	log.Printf("Successfully cloned repository to %s", targetDir)
	return nil
}

func (gr *GitResolver) setupGitAuthentication(cmd *exec.Cmd, gitInfo *GitRepositoryInfo) error {
	auth, hasAuth := gr.authManager.GetAuthForHost(gitInfo.Host)
	if !hasAuth {
		return nil
	}

	// Set up Git credentials based on auth type
	switch authType := auth.Type; authType {
	case "github-token", "gitlab-token":
		// Use token-based authentication
		authenticatedURL := strings.Replace(gitInfo.URL, "https://", fmt.Sprintf("https://%s@", auth.Token), 1)
		if !strings.HasSuffix(authenticatedURL, ".git") {
			authenticatedURL += ".git"
		}
		cmd.Args[2] = authenticatedURL // Replace the URL argument

	case "http-basic":
		// Use basic authentication
		authenticatedURL := strings.Replace(gitInfo.URL, "https://", 
			fmt.Sprintf("https://%s:%s@", auth.Username, auth.Password), 1)
		if !strings.HasSuffix(authenticatedURL, ".git") {
			authenticatedURL += ".git"
		}
		cmd.Args[2] = authenticatedURL // Replace the URL argument
	}

	return nil
}

func (gr *GitResolver) getCurrentCommitInfo(repoDir string) (map[string]string, error) {
	cmd := exec.Command("git", "log", "-1", "--format=%H|%an|%ae|%cd", "--date=iso")
	cmd.Dir = repoDir
	
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 4 {
		return nil, fmt.Errorf("unexpected git log output format")
	}

	return map[string]string{
		"commit":      parts[0],
		"author":      parts[1],
		"author_email": parts[2],
		"date":        parts[3],
	}, nil
}

func (gr *GitResolver) getGitHubRepositoryInfo(gitInfo *GitRepositoryInfo) (map[string]string, error) {
	repoURL := fmt.Sprintf("https://api.%s/repos/%s/%s",
		strings.Replace(gitInfo.Host, "github.", "github.com", 1), gitInfo.Owner, gitInfo.Repository)

	req, err := http.NewRequest("GET", repoURL, nil)
	if err != nil {
		return nil, err
	}

	gr.addGitHubAuthentication(req, gitInfo.Host)

	resp, err := gr.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var repoInfo struct {
		DefaultBranch string `json:"default_branch"`
		UpdatedAt     string `json:"updated_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
		return nil, err
	}

	return map[string]string{
		"default_branch": repoInfo.DefaultBranch,
		"updated_at":     repoInfo.UpdatedAt,
	}, nil
}

func (gr *GitResolver) determineVersionFromConstraint(constraint string, repoInfo map[string]string) string {
	// If constraint specifies a specific version, use it
	if constraint != "" && constraint != "*" && !strings.Contains(constraint, "^") && !strings.Contains(constraint, "~") {
		return constraint
	}

	// Try to extract version from commit or tag information
	if repoInfo != nil {
		if commit, exists := repoInfo["commit"]; exists && len(commit) >= 7 {
			return "dev-main#" + commit[:7]
		}
	}

	// Default to development version
	return "dev-main"
}

func (gr *GitResolver) normalizeLicense(license any) []string {
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
	case []any:
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

func (gr *GitResolver) convertAuthors(authors []Author) []types.PackageAuthor {
	result := make([]types.PackageAuthor, len(authors))
	for i, author := range authors {
		result[i] = types.PackageAuthor{
			Name:     author.Name,
			Email:    author.Email,
			Homepage: "", // Homepage field not available in parser.Author
			Role:     author.Role,
		}
	}
	return result
}

// Utility functions

func decodeBase64Content(content string) ([]byte, error) {
	// Remove whitespace from base64 content
	content = regexp.MustCompile(`\s+`).ReplaceAllString(content, "")
	
	// GitHub API returns base64 encoded content
	decoded := make([]byte, len(content))
	n, err := base64Decode([]byte(content), decoded)
	if err != nil {
		return nil, err
	}
	
	return decoded[:n], nil
}

func base64Decode(src, dst []byte) (int, error) {
	// Simple base64 decoding implementation
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	
	if len(src)%4 != 0 {
		return 0, fmt.Errorf("invalid base64 length")
	}
	
	j := 0
	for i := 0; i < len(src); i += 4 {
		var val uint32
		for k := 0; k < 4; k++ {
			c := src[i+k]
			var v uint32
			if c >= 'A' && c <= 'Z' {
				v = uint32(c - 'A')
			} else if c >= 'a' && c <= 'z' {
				v = uint32(c-'a') + 26
			} else if c >= '0' && c <= '9' {
				v = uint32(c-'0') + 52
			} else if c == '+' {
				v = 62
			} else if c == '/' {
				v = 63
			} else if c == '=' {
				v = 0
			} else {
				return 0, fmt.Errorf("invalid base64 character")
			}
			val = (val << 6) | v
		}
		
		if j < len(dst) {
			dst[j] = byte(val >> 16)
			j++
		}
		if j < len(dst) && src[i+2] != '=' {
			dst[j] = byte(val >> 8)
			j++
		}
		if j < len(dst) && src[i+3] != '=' {
			dst[j] = byte(val)
			j++
		}
	}
	
	return j, nil
}

func sanitizeForFilename(name string) string {
	// Replace invalid characters for filenames
	reg := regexp.MustCompile(`[<>:"/\\|?*]`)
	return reg.ReplaceAllString(name, "_")
}

// Cleanup removes temporary directories created by the Git resolver
func (gr *GitResolver) Cleanup() {
	if gr.tempDir != "" {
		os.RemoveAll(gr.tempDir)
	}
}