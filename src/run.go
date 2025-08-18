package src

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeClarityCE/plugin-php-sbom/src/extensions"
	"github.com/CodeClarityCE/plugin-php-sbom/src/knowledge"
	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
	"github.com/CodeClarityCE/plugin-php-sbom/src/project_finder"
	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Start is the entrypoint for the PHP SBOM plugin
// Compatible with js-sbom Start function signature
func Start(sourceCodeDir string, analysisId uuid.UUID, knowledge_db *bun.DB) types.Output {
	start := time.Now()

	log.Println("Starting PHP SBOM analysis...")
	log.Printf("PHP SBOM Debug - sourceCodeDir: %s", sourceCodeDir)

	// Check if private repository support is enabled
	enablePrivateRepos := os.Getenv("ENABLE_PRIVATE_REPOS") == "true"
	if enablePrivateRepos {
		log.Println("Private repository support enabled")
		return StartWithPrivateRepos(sourceCodeDir, analysisId, knowledge_db)
	}

	// Check if directory exists
	if _, err := os.Stat(sourceCodeDir); os.IsNotExist(err) {
		log.Printf("PHP SBOM Error - Directory does not exist: %s", sourceCodeDir)
		exceptionManager.AddError(
			"Source directory not found",
			exceptionManager.GENERIC_ERROR,
			fmt.Sprintf("The source directory does not exist: %s", sourceCodeDir),
			"SourceCodeDirDoesNotExist",
		)
		return generateFailureOutput(start, "")
	}

	// Find PHP projects in the source directory
	projectInfo, err := project_finder.FindPHPProjects(sourceCodeDir)
	if err != nil {
		exceptionManager.AddError(
			"No PHP project found in the source directory",
			exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED,
			fmt.Sprintf("Error finding PHP projects: %v", err),
			exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED,
		)
		return generateFailureOutput(start, "")
	}

	log.Printf("Found PHP project: %s (Framework: %s)", projectInfo.Name, projectInfo.Framework)

	// Check if composer.lock exists
	if projectInfo.ComposerLock == nil {
		log.Println("Warning: No composer.lock file found. Analysis will be based on composer.json only")
	}

	// Build workspaces in js-sbom compatible format
	workspaces := buildCompatibleWorkspaces(projectInfo)

	// Send package information to knowledge service for tracking
	// Extract all dependencies from all workspaces
	allDependencies := make(map[string]map[string]types.Versions)
	for _, workspace := range workspaces {
		for depName, versions := range workspace.Dependencies {
			allDependencies[depName] = versions
		}
	}
	knowledge.UpdateKnowledge(allDependencies, analysisId)

	// Detect PHP extensions
	log.Println("Detecting PHP extensions...")
	extensionInfo, err := extensions.DetectPHPExtensions(sourceCodeDir)
	if err != nil {
		log.Printf("Warning: Could not detect PHP extensions: %v", err)
		extensionInfo = &extensions.PHPExtensionInfo{
			Extensions:           make(map[string]extensions.PHPExtension),
			LoadedExtensions:     []string{},
			ConfiguredExtensions: []string{},
			CoreModules:          []string{},
		}
	}

	// Generate analysis info in js-sbom compatible format
	analysisInfo := generateCompatibleAnalysisInfo(projectInfo, extensionInfo, start)

	// Success output
	output := types.Output{
		WorkSpaces:   workspaces,
		AnalysisInfo: analysisInfo,
	}

	log.Printf("PHP SBOM analysis completed successfully. Found %d dependencies",
		getTotalDependencyCount(workspaces))

	return output
}

// buildCompatibleWorkspaces builds workspaces in js-sbom compatible format
func buildCompatibleWorkspaces(projectInfo *project_finder.ProjectInfo) map[string]types.WorkSpace {
	workspaces := make(map[string]types.WorkSpace)

	// Main workspace
	mainWorkspace := buildCompatibleWorkspace(projectInfo.ComposerJSON, projectInfo.ComposerLock)
	workspaces[types.DEFAULT_WORKSPACE_CHARACTER] = mainWorkspace

	// Additional workspaces if monorepo
	if projectInfo.IsMonorepo {
		for _, ws := range projectInfo.Workspaces {
			workspace := buildCompatibleWorkspace(ws.ComposerJSON, ws.ComposerLock)
			workspaces[ws.RelativeComposerJSON] = workspace
		}
	}

	return workspaces
}

// buildCompatibleWorkspace builds a single workspace in js-sbom compatible format
func buildCompatibleWorkspace(composerJSON *parser.ComposerJSON, composerLock *parser.ComposerLock) types.WorkSpace {
	dependencies := make(map[string]map[string]types.Versions)
	directDeps := []types.WorkSpaceDependency{}
	directDevDeps := []types.WorkSpaceDependency{}

	if composerLock != nil {
		// Process production packages from composer.lock
		for _, pkg := range composerLock.Packages {
			// Create version key like js-sbom does
			versionKey := pkg.Version

			// Create versions map for this dependency
			versions := make(map[string]types.Versions)
			versions[versionKey] = types.Versions{
				Key:          pkg.Name + VERSION_SEPARATOR + pkg.Version,
				Requires:     pkg.Require,
				Dependencies: pkg.Require, // In PHP, requires and dependencies are similar
				Optional:     false,
				Bundled:      false,
				Dev:          false,
				Prod:         true,
				Direct:       isDirectDependency(pkg.Name, composerJSON, false),
				Transitive:   !isDirectDependency(pkg.Name, composerJSON, false),
				Licenses:     parser.NormalizeLicense(pkg.License),
				// PHP-specific fields
				PHPVersion:  "",
				Type:        pkg.Type,
				Authors:     convertAuthors(pkg.Authors),
				Description: pkg.Description,
			}

			dependencies[pkg.Name] = versions
		}

		// Process dev packages from composer.lock
		for _, pkg := range composerLock.PackagesDev {
			versionKey := pkg.Version

			versions := make(map[string]types.Versions)
			versions[versionKey] = types.Versions{
				Key:          pkg.Name + VERSION_SEPARATOR + pkg.Version,
				Requires:     pkg.Require,
				Dependencies: pkg.Require,
				Optional:     false,
				Bundled:      false,
				Dev:          true,
				Prod:         false,
				Direct:       isDirectDependency(pkg.Name, composerJSON, true),
				Transitive:   !isDirectDependency(pkg.Name, composerJSON, true),
				Licenses:     parser.NormalizeLicense(pkg.License),
				// PHP-specific fields
				PHPVersion:  "",
				Type:        pkg.Type,
				Authors:     convertAuthors(pkg.Authors),
				Description: pkg.Description,
			}

			dependencies[pkg.Name] = versions
		}
	}

	// Build direct dependencies list from composer.json
	if composerJSON != nil {
		for name, version := range composerJSON.Require {
			if name != "php" && !isExtension(name) {
				directDeps = append(directDeps, types.WorkSpaceDependency{
					Name:       name,
					Version:    getResolvedVersion(name, dependencies),
					Constraint: version,
				})
			}
		}

		for name, version := range composerJSON.RequireDev {
			directDevDeps = append(directDevDeps, types.WorkSpaceDependency{
				Name:       name,
				Version:    getResolvedVersion(name, dependencies),
				Constraint: version,
			})
		}
	}

	return types.WorkSpace{
		Dependencies: dependencies,
		Start: types.Start{
			Dependencies:    directDeps,
			DevDependencies: directDevDeps,
		},
	}
}

// generateCompatibleAnalysisInfo generates analysis info in js-sbom compatible format
func generateCompatibleAnalysisInfo(projectInfo *project_finder.ProjectInfo, extensionInfo *extensions.PHPExtensionInfo, start time.Time) types.AnalysisInfo {
	end := time.Now()

	// Build paths (composer.json/composer.lock instead of package.json/package-lock.json)
	paths := types.Paths{
		Lockfile:             projectInfo.ComposerLockPath,
		PackageFile:          projectInfo.ComposerJSONPath,
		WorkSpacePackageFile: make(map[string]string),
		RelativeLockFile:     projectInfo.RelativeComposerLock,
		RelativePackageFile:  projectInfo.RelativeComposerJSON,
	}

	// Add workspace package files for monorepo
	for _, ws := range projectInfo.Workspaces {
		paths.WorkSpacePackageFile[ws.Name] = ws.ComposerJSONPath
	}

	// Build extra with PHP-specific information
	extra := types.Extra{
		// Standard fields compatible with js-sbom
		VersionSeperator:    types.VERSION_SEPARATOR,
		ImportPathSeperator: types.IMPORT_PATH_SEPARATOR,
		LockFileVersion:     1, // Composer lock version
		// PHP-specific fields
		PHPVersion: project_finder.DetectPHPVersion(projectInfo.ComposerJSON),
		Framework:  projectInfo.Framework,
		// PHAR and vendor support
		PHARFiles:          convertPHARInfos(projectInfo.PHARFiles),
		HasVendorDirectory: projectInfo.HasVendorDirectory,
		// PHP Extensions
		PHPExtensions: convertExtensionInfo(extensionInfo),
	}

	if projectInfo.ComposerLock != nil {
		extra.MinimumStability = projectInfo.ComposerLock.MinimumStability
		extra.PreferStable = projectInfo.ComposerLock.PreferStable
		extra.PluginAPIVersion = projectInfo.ComposerLock.PluginAPIVersion
		extra.ContentHash = projectInfo.ComposerLock.ContentHash
		extra.Platform = projectInfo.ComposerLock.Platform
	}

	return types.AnalysisInfo{
		Status:           codeclarity.SUCCESS,
		ProjectName:      getProjectName(projectInfo.ComposerJSON),
		WorkingDirectory: filepath.Dir(projectInfo.ComposerJSONPath),
		PackageManager:   types.PACKAGE_MANAGER,
		Time: types.Time{
			AnalysisStartTime: start.Format(time.RFC3339),
			AnalysisEndTime:   end.Format(time.RFC3339),
			AnalysisDeltaTime: float64(end.Sub(start).Nanoseconds()) / 1e9,
		},
		Errors: exceptionManager.GetErrors(),
		Paths:  paths,
		Workspaces: types.Workspaces{
			DefaultWorkspaceName:     types.DEFAULT_WORKSPACE_CHARACTER,
			SelfManagedWorkspaceName: types.SELF_MANAGED_WORKSPACE_CHARACTER,
			WorkSpacesUsed:           projectInfo.IsMonorepo,
		},
		Extra: extra,
	}
}

// generateFailureOutput generates a failure output
func generateFailureOutput(start time.Time, projectName string) types.Output {
	end := time.Now()

	return types.Output{
		WorkSpaces: make(map[string]types.WorkSpace),
		AnalysisInfo: types.AnalysisInfo{
			Status:           codeclarity.FAILURE,
			ProjectName:      projectName,
			WorkingDirectory: "",
			PackageManager:   types.PACKAGE_MANAGER,
			Time: types.Time{
				AnalysisStartTime: start.Format(time.RFC3339),
				AnalysisEndTime:   end.Format(time.RFC3339),
				AnalysisDeltaTime: float64(end.Sub(start).Nanoseconds()) / 1e9,
			},
			Errors: exceptionManager.GetErrors(),
			Paths:  types.Paths{},
			Workspaces: types.Workspaces{
				DefaultWorkspaceName:     types.DEFAULT_WORKSPACE_CHARACTER,
				SelfManagedWorkspaceName: types.SELF_MANAGED_WORKSPACE_CHARACTER,
				WorkSpacesUsed:           false,
			},
			Extra: types.Extra{
				VersionSeperator:    types.VERSION_SEPARATOR,
				ImportPathSeperator: types.IMPORT_PATH_SEPARATOR,
			},
		},
	}
}

// Helper functions

const VERSION_SEPARATOR = "@"

func getProjectName(composerJSON *parser.ComposerJSON) string {
	if composerJSON != nil && composerJSON.Name != "" {
		return composerJSON.Name
	}
	return "unknown"
}

func isDirectDependency(packageName string, composerJSON *parser.ComposerJSON, isDev bool) bool {
	if composerJSON == nil {
		return false
	}

	if isDev {
		_, exists := composerJSON.RequireDev[packageName]
		return exists
	}

	_, exists := composerJSON.Require[packageName]
	return exists
}

func isExtension(name string) bool {
	return len(name) > 4 && name[:4] == "ext-"
}

func getResolvedVersion(packageName string, dependencies map[string]map[string]types.Versions) string {
	if deps, exists := dependencies[packageName]; exists {
		// Return the first version (there should only be one in Composer)
		for version := range deps {
			return version
		}
	}
	return ""
}

func convertAuthors(authors []parser.Author) []types.Author {
	result := make([]types.Author, len(authors))
	for i, author := range authors {
		result[i] = types.Author{
			Name:  author.Name,
			Email: author.Email,
			Role:  author.Role,
		}
	}
	return result
}

// convertLicenses converts license data (can be string or array) to string slice
func convertLicenses(license any) []string {
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

func getTotalDependencyCount(workspaces map[string]types.WorkSpace) int {
	total := 0
	for _, ws := range workspaces {
		total += len(ws.Dependencies)
	}
	return total
}

// convertPHARInfos converts parser.PHARInfo to types.PHARInfo
func convertPHARInfos(pharInfos []parser.PHARInfo) []types.PHARInfo {
	result := make([]types.PHARInfo, len(pharInfos))
	for i, pharInfo := range pharInfos {
		result[i] = types.PHARInfo{
			Path:         pharInfo.Path,
			Name:         pharInfo.Name,
			Size:         pharInfo.Size,
			Modified:     pharInfo.Modified,
			Signature:    pharInfo.Signature,
			Metadata:     pharInfo.Metadata,
			MainScript:   pharInfo.MainScript,
			IsExecutable: pharInfo.IsExecutable,
		}
	}
	return result
}

// convertExtensionInfo converts extensions.PHPExtensionInfo to types.PHPExtensionInfo
func convertExtensionInfo(extInfo *extensions.PHPExtensionInfo) types.PHPExtensionInfo {
	if extInfo == nil {
		return types.PHPExtensionInfo{
			Extensions: make(map[string]types.PHPExtension),
		}
	}

	extensions := make(map[string]types.PHPExtension)
	for name, ext := range extInfo.Extensions {
		extensions[name] = types.PHPExtension{
			Name:        ext.Name,
			Version:     ext.Version,
			Type:        ext.Type,
			Status:      ext.Status,
			ZendVersion: ext.ZendVersion,
			Authors:     ext.Authors,
			Description: ext.Description,
			Metadata:    ext.Metadata,
		}
	}

	return types.PHPExtensionInfo{
		PHPVersion:           extInfo.PHPVersion,
		ZendVersion:          extInfo.ZendVersion,
		Extensions:           extensions,
		CoreModules:          extInfo.CoreModules,
		LoadedExtensions:     extInfo.LoadedExtensions,
		ConfiguredExtensions: extInfo.ConfiguredExtensions,
		BuildDate:            extInfo.BuildDate,
		Configure:            extInfo.Configure,
		ServerAPI:            extInfo.ServerAPI,
	}
}

// StartWithPrivateRepos performs PHP SBOM analysis with private repository support
func StartWithPrivateRepos(sourceCodeDir string, analysisId uuid.UUID, knowledge_db *bun.DB) types.Output {
	start := time.Now()

	log.Println("Starting enhanced PHP SBOM analysis with private repository support...")

	// Check if directory exists
	if _, err := os.Stat(sourceCodeDir); os.IsNotExist(err) {
		log.Printf("PHP SBOM Error - Directory does not exist: %s", sourceCodeDir)
		exceptionManager.AddError(
			"Source directory not found",
			exceptionManager.GENERIC_ERROR,
			fmt.Sprintf("The source directory does not exist: %s", sourceCodeDir),
			"SourceCodeDirDoesNotExist",
		)
		return generateFailureOutput(start, "")
	}

	// Create enhanced parser with private repository support
	enhancedParser, err := parser.NewEnhancedComposerParser(sourceCodeDir)
	if err != nil {
		log.Printf("Warning: Could not initialize enhanced parser, falling back to standard parsing: %v", err)
		return Start(sourceCodeDir, analysisId, knowledge_db) // Fallback to standard parsing
	}

	// Parse with private repository support
	enhancedSBOM, err := enhancedParser.ParseWithPrivateRepos()
	if err != nil {
		log.Printf("Enhanced parsing failed, falling back to standard parsing: %v", err)
		return Start(sourceCodeDir, analysisId, knowledge_db) // Fallback to standard parsing
	}

	// Log private repository statistics
	privateCount := enhancedSBOM.GetPrivatePackageCount()
	authSummary := enhancedSBOM.GetAuthenticationSummary()
	errorSummary := enhancedSBOM.GetResolutionErrorSummary()

	log.Printf("Enhanced SBOM analysis completed: %d private packages detected", privateCount)
	log.Printf("Authentication summary: %+v", authSummary)
	log.Printf("Resolution errors: %+v", errorSummary)

	// Convert enhanced SBOM to standard format for compatibility
	return convertEnhancedSBOMToStandard(enhancedSBOM, sourceCodeDir, start)
}

// convertEnhancedSBOMToStandard converts enhanced SBOM to standard format
func convertEnhancedSBOMToStandard(enhancedSBOM *parser.EnhancedSBOM, sourceCodeDir string, start time.Time) types.Output {
	// Create standard workspaces
	workspaces := make(map[string]types.WorkSpace)

	// Default workspace with regular packages
	defaultWorkspace := types.WorkSpace{
		Dependencies: make(map[string]map[string]types.Versions),
		Start: types.Start{
			Dependencies:    []types.WorkSpaceDependency{},
			DevDependencies: []types.WorkSpaceDependency{},
		},
	}

	// Convert enhanced packages to standard format
	for _, enhancedPkg := range enhancedSBOM.Packages {
		pkg := enhancedPkg.PackageInfo
		versions := map[string]types.Versions{
			pkg.Version: {
				Key:        pkg.Version,
				Licenses:   convertLicenses(pkg.License),
				Direct:     true, // Assume direct dependencies
				Prod:       true,
				Requires:   pkg.Require,
				Transitive: false,
				Optional:   false,
				Bundled:    false,
				Dev:        false,
			},
		}
		defaultWorkspace.Dependencies[pkg.Name] = versions

		// Add to start dependencies
		defaultWorkspace.Start.Dependencies = append(defaultWorkspace.Start.Dependencies, types.WorkSpaceDependency{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Constraint: "*", // Simplified constraint
		})
	}

	// Add dev packages
	for _, enhancedPkg := range enhancedSBOM.DevPackages {
		pkg := enhancedPkg.PackageInfo
		versions := map[string]types.Versions{
			pkg.Version: {
				Key:        pkg.Version,
				Licenses:   convertLicenses(pkg.License),
				Direct:     true,
				Prod:       false,
				Dev:        true,
				Requires:   pkg.RequireDev,
				Transitive: false,
				Optional:   false,
				Bundled:    false,
			},
		}
		defaultWorkspace.Dependencies[pkg.Name] = versions

		// Add to dev dependencies
		defaultWorkspace.Start.DevDependencies = append(defaultWorkspace.Start.DevDependencies, types.WorkSpaceDependency{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Constraint: "*", // Simplified constraint
		})
	}

	workspaces["default"] = defaultWorkspace

	// Generate analysis info with private repository information
	analysisInfo := types.AnalysisInfo{
		Status:           codeclarity.SUCCESS,
		ProjectName:      "Enhanced PHP Project",
		WorkingDirectory: sourceCodeDir,
		PackageManager:   "composer",
		Time: types.Time{
			AnalysisStartTime: start.Format(time.RFC3339),
			AnalysisEndTime:   time.Now().Format(time.RFC3339),
			AnalysisDeltaTime: time.Since(start).Seconds(),
		},
		Errors: exceptionManager.GetErrors(),
		Paths: types.Paths{
			Lockfile:            filepath.Join(sourceCodeDir, "composer.lock"),
			PackageFile:         filepath.Join(sourceCodeDir, "composer.json"),
			RelativeLockFile:    "composer.lock",
			RelativePackageFile: "composer.json",
		},
		Extra: types.Extra{
			VersionSeperator:    ".",
			ImportPathSeperator: "/",
			LockFileVersion:     2,
			PrivateRepositoryInfo: map[string]any{
				"private_packages_count":    enhancedSBOM.GetPrivatePackageCount(),
				"private_repositories":      len(enhancedSBOM.PrivateRepositories),
				"authentication_summary":    enhancedSBOM.GetAuthenticationSummary(),
				"resolution_error_summary":  enhancedSBOM.GetResolutionErrorSummary(),
				"private_repositories_list": enhancedSBOM.PrivateRepositories,
			},
		},
	}

	return types.Output{
		WorkSpaces:   workspaces,
		AnalysisInfo: analysisInfo,
	}
}
