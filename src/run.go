package src

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

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
	
	// Generate analysis info in js-sbom compatible format
	analysisInfo := generateCompatibleAnalysisInfo(projectInfo, start)
	
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
func generateCompatibleAnalysisInfo(projectInfo *project_finder.ProjectInfo, start time.Time) types.AnalysisInfo {
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
		PHPVersion:         project_finder.DetectPHPVersion(projectInfo.ComposerJSON),
		Framework:          projectInfo.Framework,
		// PHAR and vendor support
		PHARFiles:          convertPHARInfos(projectInfo.PHARFiles),
		HasVendorDirectory: projectInfo.HasVendorDirectory,
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