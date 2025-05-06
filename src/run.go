package codeclarity

import (
	"log"
	"time"

	outputGenerator "github.com/CodeClarityCE/plugin-template/src/outputGenerator"
	output "github.com/CodeClarityCE/plugin-template/src/types"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/uptrace/bun"
)

// Entrypoint for the plugin
func Start(knowledge_db *bun.DB, start time.Time) output.Output {
	// Start the plugin
	log.Println("Starting plugin...")

	// In case language is not supported return an error
	if false {
		exceptionManager.AddError("", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED, "", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED)
		return outputGenerator.FailureOutput(output.AnalysisInfo{}, start)
	}

	// TODO perform analysis and fill this object
	// You can adapt its type your needs
	data := map[string]output.WorkspaceInfo{
		".": {
			Info1: "info1",
			Info2: map[string][]string{
				"xyz": {"name", "value"},
			},
		},
	}

	// Generate license stats
	analysisStats := outputGenerator.GenerateAnalysisStats(data)

	// Return the analysis results
	return outputGenerator.SuccessOutput(data, analysisStats, output.AnalysisInfo{}, start)
}
