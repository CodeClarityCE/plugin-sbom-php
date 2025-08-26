package src

import (
	"log"
	"os"
	"path/filepath"

	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// PHPSBOMAnalyzer implements the SBOMAnalyzer interface for PHP projects
type PHPSBOMAnalyzer struct{}

// AnalyzeProject performs PHP SBOM analysis
func (p *PHPSBOMAnalyzer) AnalyzeProject(projectPath string, analysisId string, knowledgeDB any) (boilerplates.SBOMOutput, error) {
	log.Printf("PHP SBOM Analysis - Starting analysis for project: %s", projectPath)

	// Convert analysisId string back to UUID for compatibility with existing Start function
	analysisUUID, err := uuid.Parse(analysisId)
	if err != nil {
		log.Printf("Failed to parse analysis ID: %v", err)
		analysisUUID = uuid.New() // Generate new UUID if parsing fails
	}

	// Convert knowledgeDB to the expected type
	var knowledgeDBTyped *bun.DB
	if knowledgeDB != nil {
		if db, ok := knowledgeDB.(*bun.DB); ok {
			knowledgeDBTyped = db
		}
	}

	// Call the existing PHP SBOM Start function
	output := Start(projectPath, analysisUUID, knowledgeDBTyped)

	// Wrap the output to implement our SBOMOutput interface
	return &PHPSBOMOutput{Output: output}, nil
}

// CanAnalyze checks if this analyzer can handle the given project
func (p *PHPSBOMAnalyzer) CanAnalyze(projectPath string) bool {
	// Check for PHP project files
	composerJson := filepath.Join(projectPath, "composer.json")
	composerLock := filepath.Join(projectPath, "composer.lock")

	// At minimum, we need composer.json
	if _, err := os.Stat(composerJson); err == nil {
		log.Printf("PHP SBOM - Found composer.json at: %s", composerJson)
		return true
	}

	// Also check for composer.lock without composer.json (edge case)
	if _, err := os.Stat(composerLock); err == nil {
		log.Printf("PHP SBOM - Found composer.lock at: %s", composerLock)
		return true
	}

	log.Printf("PHP SBOM - No PHP project files found in: %s", projectPath)
	return false
}

// GetLanguage returns the language this analyzer handles
func (p *PHPSBOMAnalyzer) GetLanguage() string {
	return "PHP"
}

// DetectFramework detects the PHP framework used in the project
func (p *PHPSBOMAnalyzer) DetectFramework(projectPath string) string {
	// Read composer.json to detect framework
	composerJson := filepath.Join(projectPath, "composer.json")
	if _, err := os.Stat(composerJson); os.IsNotExist(err) {
		return ""
	}

	// This is a simplified version - the actual framework detection
	// is handled in the existing PHP SBOM code during analysis
	// We'll return empty here and let the analysis populate it
	return ""
}

// ConvertToMap converts the PHP SBOM output to map[string]any for storage
func (p *PHPSBOMAnalyzer) ConvertToMap(output boilerplates.SBOMOutput) map[string]any {
	if phpOutput, ok := output.(*PHPSBOMOutput); ok {
		return types.ConvertOutputToMap(phpOutput.Output)
	}
	return map[string]any{}
}

// GetDependencyCount returns the total number of dependencies found
func (p *PHPSBOMAnalyzer) GetDependencyCount(output boilerplates.SBOMOutput) int {
	if phpOutput, ok := output.(*PHPSBOMOutput); ok {
		total := 0
		for _, workspace := range phpOutput.Output.WorkSpaces {
			total += len(workspace.Dependencies)
		}
		return total
	}
	return 0
}

// PHPSBOMOutput wraps the existing PHP types.Output to implement SBOMOutput interface
type PHPSBOMOutput struct {
	Output types.Output
}

// GetStatus returns the analysis status
func (p *PHPSBOMOutput) GetStatus() codeclarity.AnalysisStatus {
	return p.Output.AnalysisInfo.Status
}

// GetFramework returns the detected framework
func (p *PHPSBOMOutput) GetFramework() string {
	return p.Output.AnalysisInfo.Extra.Framework
}
