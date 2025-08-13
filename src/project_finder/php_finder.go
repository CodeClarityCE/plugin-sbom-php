package project_finder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
)

// ProjectInfo contains information about a PHP project
type ProjectInfo struct {
	Name                 string
	Version              string
	Description          string
	RootDir              string
	ComposerJSONPath     string
	ComposerLockPath     string
	RelativeComposerJSON string
	RelativeComposerLock string
	ComposerJSON         *parser.ComposerJSON
	ComposerLock         *parser.ComposerLock
	Framework            string // Laravel, Symfony, WordPress, etc.
	IsMonorepo           bool
	Workspaces           []WorkspaceInfo
}

// WorkspaceInfo represents a workspace in a monorepo
type WorkspaceInfo struct {
	Name                 string
	Path                 string
	ComposerJSONPath     string
	ComposerLockPath     string
	RelativeComposerJSON string
	RelativeComposerLock string
	ComposerJSON         *parser.ComposerJSON
	ComposerLock         *parser.ComposerLock
}

// FindPHPProjects finds all PHP projects in the given directory
func FindPHPProjects(rootDir string) (*ProjectInfo, error) {
	composerJSONFiles, composerLockFiles, err := parser.FindComposerFiles(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find composer files: %w", err)
	}

	if len(composerJSONFiles) == 0 {
		return nil, fmt.Errorf("no composer.json files found")
	}

	// Find the root project (closest to rootDir)
	rootComposerJSON := findRootComposerFile(rootDir, composerJSONFiles)
	rootComposerLock := findMatchingLockFile(rootComposerJSON, composerLockFiles)

	// Parse root composer.json
	composerData, err := parser.ParseComposerJSON(rootComposerJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root composer.json: %w", err)
	}

	projectInfo := &ProjectInfo{
		Name:                 composerData.Name,
		Version:              composerData.Version,
		Description:          composerData.Description,
		RootDir:              rootDir,
		ComposerJSONPath:     rootComposerJSON,
		ComposerLockPath:     rootComposerLock,
		RelativeComposerJSON: getRelativePath(rootDir, rootComposerJSON),
		RelativeComposerLock: getRelativePath(rootDir, rootComposerLock),
		ComposerJSON:         composerData,
		Framework:            detectFramework(composerData),
		IsMonorepo:           false,
		Workspaces:           []WorkspaceInfo{},
	}

	// Parse composer.lock if it exists
	if rootComposerLock != "" {
		lockData, err := parser.ParseComposerLock(rootComposerLock)
		if err == nil {
			projectInfo.ComposerLock = lockData
		}
	}

	// Check for monorepo/workspaces
	if len(composerJSONFiles) > 1 {
		projectInfo.IsMonorepo = true
		projectInfo.Workspaces = findWorkspaces(rootDir, rootComposerJSON, composerJSONFiles, composerLockFiles)
	}

	return projectInfo, nil
}

// findRootComposerFile finds the composer.json closest to the root directory
func findRootComposerFile(rootDir string, composerFiles []string) string {
	var rootFile string
	minDepth := int(^uint(0) >> 1) // Max int

	for _, file := range composerFiles {
		relPath, _ := filepath.Rel(rootDir, file)
		depth := strings.Count(relPath, string(os.PathSeparator))
		if depth < minDepth {
			minDepth = depth
			rootFile = file
		}
	}

	return rootFile
}

// findMatchingLockFile finds the composer.lock file in the same directory as composer.json
func findMatchingLockFile(composerJSONPath string, lockFiles []string) string {
	dir := filepath.Dir(composerJSONPath)
	expectedLockPath := filepath.Join(dir, "composer.lock")

	for _, lockFile := range lockFiles {
		if lockFile == expectedLockPath {
			return lockFile
		}
		// Also try absolute path matching
		absExpected, _ := filepath.Abs(expectedLockPath)
		absLockFile, _ := filepath.Abs(lockFile)
		if absExpected == absLockFile {
			return lockFile
		}
	}

	return ""
}

// detectFramework detects the PHP framework based on composer.json dependencies
func detectFramework(composerData *parser.ComposerJSON) string {
	// Check for CakePHP (put this first since it's what we're testing)
	if _, ok := composerData.Require["cakephp/cakephp"]; ok {
		return "CakePHP"
	}

	// Check for Laravel
	if _, ok := composerData.Require["laravel/framework"]; ok {
		return "Laravel"
	}

	// Check for Symfony
	if _, ok := composerData.Require["symfony/framework-bundle"]; ok {
		return "Symfony"
	}
	// Also check for Symfony components
	for pkg := range composerData.Require {
		if strings.HasPrefix(pkg, "symfony/") {
			return "Symfony Components"
		}
	}

	// Check for WordPress
	if composerData.Type == "wordpress-plugin" || composerData.Type == "wordpress-theme" {
		return "WordPress"
	}
	if _, ok := composerData.Require["johnpbloch/wordpress"]; ok {
		return "WordPress"
	}

	// Check for Drupal
	if _, ok := composerData.Require["drupal/core"]; ok {
		return "Drupal"
	}
	if composerData.Type == "drupal-module" || composerData.Type == "drupal-theme" {
		return "Drupal"
	}

	// Check for Laminas/Zend
	if _, ok := composerData.Require["laminas/laminas-mvc"]; ok {
		return "Laminas"
	}
	if _, ok := composerData.Require["zendframework/zend-mvc"]; ok {
		return "Zend Framework"
	}

	// Check for Slim
	if _, ok := composerData.Require["slim/slim"]; ok {
		return "Slim"
	}

	// Check for CodeIgniter
	if _, ok := composerData.Require["codeigniter4/framework"]; ok {
		return "CodeIgniter 4"
	}

	// Check for Yii
	if _, ok := composerData.Require["yiisoft/yii2"]; ok {
		return "Yii2"
	}

	// Check for Lumen
	if _, ok := composerData.Require["laravel/lumen-framework"]; ok {
		return "Lumen"
	}

	return "Generic PHP"
}

// findWorkspaces finds all workspace projects in a monorepo
func findWorkspaces(rootDir, rootComposerPath string, composerFiles, lockFiles []string) []WorkspaceInfo {
	var workspaces []WorkspaceInfo
	rootComposerDir := filepath.Dir(rootComposerPath)

	for _, composerFile := range composerFiles {
		// Skip the root composer.json
		if composerFile == rootComposerPath {
			continue
		}

		// Skip vendor directories
		if strings.Contains(composerFile, "/vendor/") {
			continue
		}

		composerData, err := parser.ParseComposerJSON(composerFile)
		if err != nil {
			continue
		}

		workspace := WorkspaceInfo{
			Name:                 composerData.Name,
			Path:                 filepath.Dir(composerFile),
			ComposerJSONPath:     composerFile,
			ComposerLockPath:     findMatchingLockFile(composerFile, lockFiles),
			RelativeComposerJSON: getRelativePath(rootComposerDir, composerFile),
			ComposerJSON:         composerData,
		}

		// Parse workspace composer.lock if it exists
		if workspace.ComposerLockPath != "" {
			workspace.RelativeComposerLock = getRelativePath(rootComposerDir, workspace.ComposerLockPath)
			lockData, err := parser.ParseComposerLock(workspace.ComposerLockPath)
			if err == nil {
				workspace.ComposerLock = lockData
			}
		}

		workspaces = append(workspaces, workspace)
	}

	return workspaces
}

// getRelativePath gets the relative path from base to target
func getRelativePath(base, target string) string {
	relPath, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return relPath
}

// DetectPHPVersion detects the PHP version requirement from composer.json
func DetectPHPVersion(composerData *parser.ComposerJSON) string {
	if phpVersion, ok := composerData.Require["php"]; ok {
		return phpVersion
	}
	return ""
}