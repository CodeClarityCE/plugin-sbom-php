package extensions

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
)

// PHPExtension represents a PHP extension with its version and metadata
type PHPExtension struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Type        string            `json:"type"`   // "core", "bundled", "external"
	Status      string            `json:"status"` // "enabled", "disabled"
	ZendVersion string            `json:"zend_version,omitempty"`
	Authors     []string          `json:"authors,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PHPExtensionInfo contains comprehensive information about PHP and its extensions
type PHPExtensionInfo struct {
	PHPVersion           string                  `json:"php_version"`
	ZendVersion          string                  `json:"zend_version"`
	Extensions           map[string]PHPExtension `json:"extensions"`
	CoreModules          []string                `json:"core_modules"`
	LoadedExtensions     []string                `json:"loaded_extensions"`
	ConfiguredExtensions []string                `json:"configured_extensions"`
	BuildDate            string                  `json:"build_date,omitempty"`
	Configure            string                  `json:"configure,omitempty"`
	ServerAPI            string                  `json:"server_api,omitempty"`
}

// DetectPHPExtensions discovers PHP extensions and their versions from the project environment
func DetectPHPExtensions(sourceCodeDir string) (*PHPExtensionInfo, error) {
	info := &PHPExtensionInfo{
		Extensions:           make(map[string]PHPExtension),
		CoreModules:          []string{},
		LoadedExtensions:     []string{},
		ConfiguredExtensions: []string{},
	}

	// Try multiple methods to detect PHP extensions
	if err := detectFromPHPInfo(info); err != nil {
		log.Printf("Warning: Could not detect extensions from php -m: %v", err)
	}

	if err := detectFromPHPVersion(info); err != nil {
		log.Printf("Warning: Could not detect PHP version: %v", err)
	}

	if err := detectFromComposerJSON(sourceCodeDir, info); err != nil {
		log.Printf("Warning: Could not detect extension requirements from composer.json: %v", err)
	}

	if err := detectFromDockerfile(sourceCodeDir, info); err != nil {
		log.Printf("Debug: No Dockerfile found or could not parse: %v", err)
	}

	if err := detectFromPHPIni(sourceCodeDir, info); err != nil {
		log.Printf("Debug: No php.ini found or could not parse: %v", err)
	}

	// Enrich extension information
	enrichExtensionInfo(info)

	return info, nil
}

// detectFromPHPInfo uses php -m to list loaded modules
func detectFromPHPInfo(info *PHPExtensionInfo) error {
	// Get loaded modules
	cmd := exec.Command("php", "-m")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run php -m: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var currentSection string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		switch currentSection {
		case "PHP Modules":
			info.LoadedExtensions = append(info.LoadedExtensions, line)
			info.Extensions[line] = PHPExtension{
				Name:   line,
				Status: "enabled",
				Type:   "unknown", // Will be enriched later
			}
		case "Zend Modules":
			info.Extensions[line] = PHPExtension{
				Name:   line,
				Status: "enabled",
				Type:   "zend",
			}
		}
	}

	return nil
}

// detectFromPHPVersion gets PHP version information
func detectFromPHPVersion(info *PHPExtensionInfo) error {
	cmd := exec.Command("php", "-v")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run php -v: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		// Parse PHP version from first line
		// Example: "PHP 8.1.12 (cli) (built: Oct 28 2022 17:39:28) ( NTS )"
		versionRegex := regexp.MustCompile(`PHP\s+(\d+\.\d+\.\d+)`)
		matches := versionRegex.FindStringSubmatch(lines[0])
		if len(matches) > 1 {
			info.PHPVersion = matches[1]
		}

		// Parse Zend Engine version if present
		zendRegex := regexp.MustCompile(`with Zend OPcache v(\d+\.\d+\.\d+)`)
		for _, line := range lines {
			matches := zendRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				info.ZendVersion = matches[1]
				break
			}
		}
	}

	return nil
}

// detectFromComposerJSON reads extension requirements from composer.json
func detectFromComposerJSON(sourceCodeDir string, info *PHPExtensionInfo) error {
	// Use the parser package to find and parse composer.json
	composerJSONFiles, _, err := parser.FindComposerFiles(sourceCodeDir)
	if err != nil || len(composerJSONFiles) == 0 {
		return fmt.Errorf("no composer.json files found")
	}

	// Parse the main composer.json file
	composerData, err := parser.ParseComposerJSON(composerJSONFiles[0])
	if err != nil {
		return fmt.Errorf("failed to parse composer.json: %w", err)
	}

	// Extract PHP extension requirements
	for packageName, version := range composerData.Require {
		if extName, found := strings.CutPrefix(packageName, "ext-"); found {

			// Add extension to our info
			info.Extensions[extName] = PHPExtension{
				Name:    extName,
				Version: version,
				Type:    "external", // Extensions from composer are typically external
				Status:  "required", // Required by composer.json
			}

			// Also add to configured extensions list
			info.ConfiguredExtensions = append(info.ConfiguredExtensions, extName)

			log.Printf("Detected extension from composer.json: %s (%s)", extName, version)
		}

		// Also check for PHP version requirement
		if packageName == "php" && info.PHPVersion == "" {
			info.PHPVersion = version
			log.Printf("Detected PHP version requirement from composer.json: %s", version)
		}
	}

	// Also check require-dev for development extensions
	for packageName, version := range composerData.RequireDev {
		if extName, found := strings.CutPrefix(packageName, "ext-"); found {

			// Only add if not already present (require takes precedence over require-dev)
			if _, exists := info.Extensions[extName]; !exists {
				info.Extensions[extName] = PHPExtension{
					Name:    extName,
					Version: version,
					Type:    "external",
					Status:  "dev-required", // Required for development only
				}

				info.ConfiguredExtensions = append(info.ConfiguredExtensions, extName)
				log.Printf("Detected dev extension from composer.json: %s (%s)", extName, version)
			}
		}
	}

	return nil
}

// detectFromDockerfile looks for extension installations in Dockerfile
func detectFromDockerfile(_ string, _ *PHPExtensionInfo) error {
	// Look for docker-php-ext-install commands in Dockerfile
	// This is common in containerized PHP applications

	return nil // Placeholder
}

// detectFromPHPIni parses php.ini files for extension configuration
func detectFromPHPIni(_ string, _ *PHPExtensionInfo) error {
	// Parse php.ini files for extension= directives

	return nil // Placeholder
}

// enrichExtensionInfo adds additional metadata to extensions
func enrichExtensionInfo(info *PHPExtensionInfo) {
	// Add version information for known extensions
	for name, ext := range info.Extensions {
		enriched := ext

		// Try to get version information for specific extensions
		if version := getExtensionVersion(name); version != "" {
			enriched.Version = version
		}

		// Categorize extension type
		enriched.Type = categorizeExtension(name)

		// Add description
		enriched.Description = getExtensionDescription(name)

		info.Extensions[name] = enriched
	}
}

// getExtensionVersion attempts to get version for a specific extension
func getExtensionVersion(extensionName string) string {
	// Try to get extension version using php -r
	script := fmt.Sprintf("if (extension_loaded('%s')) { $info = new ReflectionExtension('%s'); echo $info->getVersion(); }", extensionName, extensionName)
	cmd := exec.Command("php", "-r", script)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	version := strings.TrimSpace(string(output))
	if version == "" || strings.Contains(version, "Error") {
		return ""
	}

	return version
}

// categorizeExtension determines the type of extension
func categorizeExtension(name string) string {
	coreExtensions := map[string]bool{
		"core": true, "date": true, "pcre": true, "reflection": true,
		"spl": true, "standard": true, "filter": true, "hash": true,
		"json": true, "libxml": true, "session": true, "tokenizer": true,
	}

	bundledExtensions := map[string]bool{
		"bcmath": true, "calendar": true, "ctype": true, "dom": true,
		"fileinfo": true, "ftp": true, "gd": true, "gettext": true,
		"iconv": true, "intl": true, "mbstring": true, "mysql": true,
		"mysqli": true, "openssl": true, "pdo": true, "pdo_mysql": true,
		"pdo_sqlite": true, "simplexml": true, "soap": true, "sqlite3": true,
		"xml": true, "xmlreader": true, "xmlwriter": true, "zip": true,
		"zlib": true, "curl": true, "exif": true,
	}

	if coreExtensions[name] {
		return "core"
	}
	if bundledExtensions[name] {
		return "bundled"
	}

	return "external"
}

// getExtensionDescription provides descriptions for common extensions
func getExtensionDescription(name string) string {
	descriptions := map[string]string{
		"curl":      "Client URL Library for HTTP requests",
		"gd":        "Graphics Draw library for image manipulation",
		"json":      "JavaScript Object Notation support",
		"mbstring":  "Multi-byte string handling",
		"mysqli":    "MySQL Improved extension",
		"openssl":   "OpenSSL cryptographic functions",
		"pdo":       "PHP Data Objects database abstraction",
		"xml":       "XML parser support",
		"zip":       "ZIP archive manipulation",
		"zlib":      "Compression library",
		"intl":      "Internationalization extension",
		"soap":      "SOAP protocol support",
		"bcmath":    "Arbitrary precision mathematics",
		"calendar":  "Calendar conversion functions",
		"ctype":     "Character type checking",
		"dom":       "Document Object Model manipulation",
		"fileinfo":  "File information detection",
		"filter":    "Data filtering and validation",
		"ftp":       "File Transfer Protocol support",
		"gettext":   "GNU gettext message translation",
		"hash":      "HASH message digest algorithms",
		"iconv":     "Character set conversion",
		"libxml":    "XML library support",
		"pcre":      "Perl Compatible Regular Expressions",
		"session":   "Session handling",
		"simplexml": "Simple XML parser",
		"spl":       "Standard PHP Library",
		"sqlite3":   "SQLite3 database support",
		"tokenizer": "PHP tokenizer",
		"xmlreader": "XMLReader support",
		"xmlwriter": "XMLWriter support",
		"exif":      "EXIF metadata from images",
	}

	if desc, exists := descriptions[name]; exists {
		return desc
	}

	return ""
}

// GetExtensionPackageURL generates a PackageURL for PHP extensions (for vulnerability tracking)
func (ext PHPExtension) GetExtensionPackageURL() string {
	// Generate PackageURL for PHP extension following purl spec
	// Format: pkg:php-ext/extension-name@version
	if ext.Version != "" {
		return fmt.Sprintf("pkg:php-ext/%s@%s", ext.Name, ext.Version)
	}
	return fmt.Sprintf("pkg:php-ext/%s", ext.Name)
}

// IsVulnerabilityRelevant checks if an extension is relevant for vulnerability tracking
func (ext PHPExtension) IsVulnerabilityRelevant() bool {
	// Core extensions that are commonly vulnerable
	vulnerableExtensions := map[string]bool{
		"curl":      true,
		"openssl":   true,
		"gd":        true,
		"xml":       true,
		"libxml":    true,
		"zip":       true,
		"mysqli":    true,
		"pdo":       true,
		"soap":      true,
		"ftp":       true,
		"iconv":     true,
		"mbstring":  true,
		"fileinfo":  true,
		"exif":      true,
		"filter":    true,
		"hash":      true,
		"intl":      true,
		"json":      true,
		"session":   true,
		"sqlite3":   true,
		"xmlreader": true,
		"xmlwriter": true,
		"simplexml": true,
		"dom":       true,
	}

	return vulnerableExtensions[ext.Name] || ext.Type == "external"
}
