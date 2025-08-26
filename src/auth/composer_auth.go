package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AuthType represents different authentication methods for private repositories
type AuthType string

const (
	HTTPBasic      AuthType = "http-basic"
	Bearer         AuthType = "bearer"
	GitLabToken    AuthType = "gitlab-token"
	GitHubOAuth    AuthType = "github-oauth"
	GitHubToken    AuthType = "github-token"
	BitbucketOAuth AuthType = "bitbucket-oauth"
)

// ComposerAuth represents authentication credentials for a repository
type ComposerAuth struct {
	Type     AuthType `json:"type"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	Token    string   `json:"token,omitempty"`
	URL      string   `json:"url"`
}

// ComposerRepository represents a repository configuration from composer.json
type ComposerRepository struct {
	Type    string         `json:"type"`
	URL     string         `json:"url,omitempty"`
	Options map[string]any `json:"options,omitempty"`
	Only    []string       `json:"only,omitempty"`
	Exclude []string       `json:"exclude,omitempty"`
}

// ComposerConfig represents the complete authentication and repository configuration
type ComposerConfig struct {
	Repositories []ComposerRepository    `json:"repositories"`
	Auth         map[string]ComposerAuth `json:"auth"`
	Config       map[string]any          `json:"config"`
}

// SecurityConfig represents security settings for private repository access
type SecurityConfig struct {
	AllowPrivateRepos bool     `json:"allow_private_repos"`
	TrustedHosts      []string `json:"trusted_hosts"`
	DisableSSLVerify  bool     `json:"disable_ssl_verify"`
	CredentialTimeout int      `json:"credential_timeout_seconds"`
}

// AuthManager manages authentication for private Composer repositories
type AuthManager struct {
	config   *ComposerConfig
	security *SecurityConfig
}

// NewAuthManager creates a new authentication manager
func NewAuthManager() *AuthManager {
	return &AuthManager{
		config: &ComposerConfig{
			Repositories: []ComposerRepository{},
			Auth:         make(map[string]ComposerAuth),
			Config:       make(map[string]any),
		},
		security: &SecurityConfig{
			AllowPrivateRepos: true,
			TrustedHosts:      []string{},
			DisableSSLVerify:  false,
			CredentialTimeout: 3600, // 1 hour default
		},
	}
}

// LoadFromComposerJSON loads repository configuration from composer.json
func (am *AuthManager) LoadFromComposerJSON(composerJSONPath string) error {
	data, err := os.ReadFile(composerJSONPath)
	if err != nil {
		return fmt.Errorf("failed to read composer.json: %w", err)
	}

	var composerData struct {
		Repositories []ComposerRepository `json:"repositories,omitempty"`
		Config       map[string]any       `json:"config,omitempty"`
	}

	if err := json.Unmarshal(data, &composerData); err != nil {
		return fmt.Errorf("failed to parse composer.json: %w", err)
	}

	am.config.Repositories = composerData.Repositories
	if composerData.Config != nil {
		am.config.Config = composerData.Config
	}

	return nil
}

// LoadFromAuthJSON loads authentication credentials from auth.json
func (am *AuthManager) LoadFromAuthJSON(projectDir string) error {
	// Look for auth.json in multiple locations
	authPaths := []string{
		filepath.Join(projectDir, "auth.json"),
		filepath.Join(os.Getenv("HOME"), ".composer", "auth.json"),
		filepath.Join(os.Getenv("COMPOSER_HOME"), "auth.json"),
	}

	// Also check environment variable for auth.json path
	if authPath := os.Getenv("COMPOSER_AUTH_JSON"); authPath != "" {
		authPaths = append([]string{authPath}, authPaths...)
	}

	for _, authPath := range authPaths {
		if _, err := os.Stat(authPath); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(authPath)
		if err != nil {
			continue // Try next path
		}

		var authData struct {
			HTTPBasic map[string]struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"http-basic,omitempty"`
			GitHubOAuth map[string]string `json:"github-oauth,omitempty"`
			GitLabToken map[string]string `json:"gitlab-token,omitempty"`
			Bearer      map[string]string `json:"bearer,omitempty"`
		}

		if err := json.Unmarshal(data, &authData); err != nil {
			continue // Try next path
		}

		// Convert auth.json format to our internal format
		if am.config.Auth == nil {
			am.config.Auth = make(map[string]ComposerAuth)
		}

		// HTTP Basic Auth
		for host, creds := range authData.HTTPBasic {
			am.config.Auth[host] = ComposerAuth{
				Type:     HTTPBasic,
				Username: creds.Username,
				Password: creds.Password,
				URL:      host,
			}
		}

		// GitHub OAuth
		for host, token := range authData.GitHubOAuth {
			am.config.Auth[host] = ComposerAuth{
				Type:  GitHubOAuth,
				Token: token,
				URL:   host,
			}
		}

		// GitLab Token
		for host, token := range authData.GitLabToken {
			am.config.Auth[host] = ComposerAuth{
				Type:  GitLabToken,
				Token: token,
				URL:   host,
			}
		}

		// Bearer Token
		for host, token := range authData.Bearer {
			am.config.Auth[host] = ComposerAuth{
				Type:  Bearer,
				Token: token,
				URL:   host,
			}
		}

		return nil // Successfully loaded auth from this file
	}

	// No auth.json found, but that's not necessarily an error
	return nil
}

// LoadFromEnvironment loads authentication from environment variables
func (am *AuthManager) LoadFromEnvironment() error {
	// Support COMPOSER_AUTH environment variable (JSON format)
	if composerAuth := os.Getenv("COMPOSER_AUTH"); composerAuth != "" {
		var authData map[string]any
		if err := json.Unmarshal([]byte(composerAuth), &authData); err != nil {
			return fmt.Errorf("failed to parse COMPOSER_AUTH: %w", err)
		}

		// Process the auth data similar to auth.json
		return am.processEnvironmentAuth(authData)
	}

	// Support individual environment variables for common hosts
	am.loadIndividualEnvVars()

	return nil
}

// processEnvironmentAuth processes authentication data from environment variables
func (am *AuthManager) processEnvironmentAuth(authData map[string]any) error {
	if am.config.Auth == nil {
		am.config.Auth = make(map[string]ComposerAuth)
	}

	// Process http-basic auth
	if httpBasic, ok := authData["http-basic"].(map[string]any); ok {
		for host, credsData := range httpBasic {
			if creds, ok := credsData.(map[string]any); ok {
				username, _ := creds["username"].(string)
				password, _ := creds["password"].(string)
				am.config.Auth[host] = ComposerAuth{
					Type:     HTTPBasic,
					Username: username,
					Password: password,
					URL:      host,
				}
			}
		}
	}

	// Process other auth types similarly...
	return nil
}

// loadIndividualEnvVars loads authentication from individual environment variables
func (am *AuthManager) loadIndividualEnvVars() {
	if am.config.Auth == nil {
		am.config.Auth = make(map[string]ComposerAuth)
	}

	// GitHub credentials
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		am.config.Auth["github.com"] = ComposerAuth{
			Type:  GitHubToken,
			Token: token,
			URL:   "github.com",
		}
	}

	// GitLab credentials
	if token := os.Getenv("GITLAB_TOKEN"); token != "" {
		host := os.Getenv("GITLAB_HOST")
		if host == "" {
			host = "gitlab.com"
		}
		am.config.Auth[host] = ComposerAuth{
			Type:  GitLabToken,
			Token: token,
			URL:   host,
		}
	}

	// Private Packagist credentials
	if username := os.Getenv("PACKAGIST_USERNAME"); username != "" {
		if password := os.Getenv("PACKAGIST_PASSWORD"); password != "" {
			host := os.Getenv("PACKAGIST_HOST")
			if host == "" {
				host = "packagist.org"
			}
			am.config.Auth[host] = ComposerAuth{
				Type:     HTTPBasic,
				Username: username,
				Password: password,
				URL:      host,
			}
		}
	}
}

// GetAuthForHost returns authentication credentials for a given host
func (am *AuthManager) GetAuthForHost(host string) (*ComposerAuth, bool) {
	// Normalize host (remove protocol, trailing slash, etc.)
	normalizedHost := am.normalizeHost(host)

	// Check exact match first
	if auth, exists := am.config.Auth[normalizedHost]; exists {
		return &auth, true
	}

	// Check for wildcard or subdomain matches
	for authHost, auth := range am.config.Auth {
		if am.hostMatches(normalizedHost, authHost) {
			return &auth, true
		}
	}

	return nil, false
}

// normalizeHost normalizes a host URL for comparison
func (am *AuthManager) normalizeHost(host string) string {
	// Remove protocol
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Remove trailing slash and path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Remove port for standard ports
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")

	return strings.ToLower(host)
}

// hostMatches checks if a host matches an auth host pattern
func (am *AuthManager) hostMatches(host, authHost string) bool {
	// Simple wildcard matching
	if domain, found := strings.CutPrefix(authHost, "*."); found {
		return strings.HasSuffix(host, "."+domain) || host == domain
	}

	// Exact match
	return host == authHost
}

// GetRepositories returns all configured repositories
func (am *AuthManager) GetRepositories() []ComposerRepository {
	return am.config.Repositories
}

// IsPrivateRepository checks if a repository is private based on its URL and auth requirements
func (am *AuthManager) IsPrivateRepository(repo ComposerRepository) bool {
	if repo.URL == "" {
		return false
	}

	host := am.normalizeHost(repo.URL)
	_, hasAuth := am.GetAuthForHost(host)

	// Consider a repository private if:
	// 1. It has authentication configured
	// 2. It's not a known public repository
	return hasAuth || am.isKnownPrivateHost(host)
}

// isKnownPrivateHost checks if a host is known to be private
func (am *AuthManager) isKnownPrivateHost(host string) bool {
	knownPrivatePatterns := []string{
		"repo.packagist.com",
		"repo.company.com",
		"gitlab.company.com",
		"github.company.com",
		"packagist.company.com",
	}

	for _, pattern := range knownPrivatePatterns {
		if strings.Contains(host, "company") || strings.Contains(host, "repo") {
			return true
		}
		if strings.HasSuffix(host, pattern) {
			return true
		}
	}

	return false
}

// GetSecurityConfig returns the security configuration
func (am *AuthManager) GetSecurityConfig() *SecurityConfig {
	return am.security
}

// SetSecurityConfig updates the security configuration
func (am *AuthManager) SetSecurityConfig(config *SecurityConfig) {
	am.security = config
}
