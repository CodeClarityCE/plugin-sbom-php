package types

import (
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
)

// Output represents the complete SBOM output for PHP projects
// Compatible with js-sbom structure
type Output struct {
	WorkSpaces   map[string]WorkSpace `json:"workspaces"`
	AnalysisInfo AnalysisInfo         `json:"analysis_info"`
}

// WorkSpace represents a single workspace/project in the SBOM
// Compatible with js-sbom WorkSpace structure
type WorkSpace struct {
	Dependencies map[string]map[string]Versions `json:"dependencies"`
	Start        Start                          `json:"start"`
}

// Versions represents dependency version information
// Compatible with js-sbom Versions structure with PHP-specific fields
type Versions struct {
	Key          string            `json:"key"`
	Requires     map[string]string `json:"requires"`
	Dependencies map[string]string `json:"dependencies"`
	Optional     bool              `json:"optional"`
	Bundled      bool              `json:"bundled"`
	Dev          bool              `json:"dev"`
	Prod         bool              `json:"prod"`
	Direct       bool              `json:"direct"`
	Transitive   bool              `json:"transitive"`
	Licenses     []string          `json:"licenses"`
	// PHP-specific fields (will be filtered in extra processing)
	PHPVersion  string   `json:"php_version,omitempty"`
	Type        string   `json:"type,omitempty"`
	Authors     []Author `json:"authors,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Start represents direct dependencies
type Start struct {
	Dependencies    []WorkSpaceDependency `json:"dependencies"`
	DevDependencies []WorkSpaceDependency `json:"dev_dependencies"`
}

// WorkSpaceDependency represents a direct dependency
type WorkSpaceDependency struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Constraint string `json:"constraint"`
}

// Author represents package author information (PHP-specific)
type Author struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	Role  string `json:"role,omitempty"`
}

// AnalysisInfo contains metadata about the analysis
// Compatible with js-sbom AnalysisInfo structure
type AnalysisInfo struct {
	Status           codeclarity.AnalysisStatus `json:"status"`
	ProjectName      string                     `json:"project_name"`
	WorkingDirectory string                     `json:"working_directory"`
	PackageManager   string                     `json:"package_manager"`
	Time             Time                       `json:"time"`
	Errors           []exceptions.Error         `json:"errors"`
	Paths            Paths                      `json:"paths"`
	Workspaces       Workspaces                 `json:"workspaces"`
	Extra            Extra                      `json:"extra"`
}

// Paths contains file path information
// Adapted for PHP (composer.json/composer.lock instead of package.json/package-lock.json)
type Paths struct {
	Lockfile             string            `json:"lock_file_path"`
	PackageFile          string            `json:"package_file_path"`
	WorkSpacePackageFile map[string]string `json:"work_space_package_file_paths"`
	RelativeLockFile     string            `json:"relative_lock_file_path"`
	RelativePackageFile  string            `json:"relative_package_file_path"`
}

// Extra contains additional metadata
// PHP-specific information goes here
type Extra struct {
	// Standard fields (compatible with js-sbom)
	VersionSeperator    string `json:"version_seperator"`
	ImportPathSeperator string `json:"import_path_seperator"`
	LockFileVersion     int    `json:"lock_file_version"`
	// PHP-specific fields
	PHPVersion           string            `json:"php_version,omitempty"`
	Framework            string            `json:"framework,omitempty"`
	MinimumStability     string            `json:"minimum_stability,omitempty"`
	PreferStable         bool              `json:"prefer_stable,omitempty"`
	PluginAPIVersion     string            `json:"plugin_api_version,omitempty"`
	ContentHash          string            `json:"content_hash,omitempty"`
	Platform             map[string]string `json:"platform,omitempty"`
	Statistics           Statistics        `json:"statistics,omitempty"`
	// PHAR and vendor support
	PHARFiles            []PHARInfo        `json:"phar_files,omitempty"`
	HasVendorDirectory   bool              `json:"has_vendor_directory,omitempty"`
}

// PHARInfo represents information about a PHAR archive
type PHARInfo struct {
	Path         string                 `json:"path"`
	Name         string                 `json:"name"`
	Size         int64                  `json:"size"`
	Modified     string                 `json:"modified"`
	Signature    string                 `json:"signature"`
	Metadata     map[string]interface{} `json:"metadata"`
	MainScript   string                 `json:"main_script"`
	IsExecutable bool                   `json:"is_executable"`
}

// Workspaces contains workspace information
// Compatible with js-sbom structure
type Workspaces struct {
	DefaultWorkspaceName     string `json:"default_workspace_name"`
	SelfManagedWorkspaceName string `json:"self_managed_workspace_name"`
	WorkSpacesUsed           bool   `json:"work_spaces_used"`
}

// Time contains timing information
// Compatible with js-sbom Time structure
type Time struct {
	AnalysisStartTime string  `json:"analysis_start_time"`
	AnalysisEndTime   string  `json:"analysis_end_time"`
	AnalysisDeltaTime float64 `json:"analysis_delta_time"`
}

// Statistics contains analysis statistics (PHP-specific, goes in Extra)
type Statistics struct {
	TotalPackages          int            `json:"total_packages"`
	DirectPackages         int            `json:"direct_packages"`
	TransitivePackages     int            `json:"transitive_packages"`
	DevPackages            int            `json:"dev_packages"`
	UniqueAuthors          int            `json:"unique_authors"`
	UniqueLicenses         int            `json:"unique_licenses"`
	LicenseBreakdown       map[string]int `json:"license_breakdown"`
	TypeBreakdown          map[string]int `json:"type_breakdown"`
	VulnerablePackages     int            `json:"vulnerable_packages"`
	OutdatedPackages       int            `json:"outdated_packages"`
}

// Constants for PHP SBOM (compatible with js-sbom patterns)
const (
	DEFAULT_WORKSPACE_CHARACTER      = "."
	SELF_MANAGED_WORKSPACE_CHARACTER = "self-managed"
	VERSION_SEPARATOR                = "@"
	IMPORT_PATH_SEPARATOR            = "/"
	PACKAGE_MANAGER                  = "composer"
)

// ConvertOutputToMap converts the PHP SBOM output to map (compatible with js-sbom)
func ConvertOutputToMap(output Output) map[string]interface{} {
	outputMap := make(map[string]interface{})
	outputMap["workspaces"] = output.WorkSpaces
	outputMap["analysis_info"] = output.AnalysisInfo
	return outputMap
}