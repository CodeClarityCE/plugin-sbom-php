package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	codeclarity_src "github.com/CodeClarityCE/plugin-php-sbom/src"
	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
	"github.com/CodeClarityCE/utility-types/ecosystem"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
)

// PHPSBOMAnalysisHandler implements the AnalysisHandler interface
type PHPSBOMAnalysisHandler struct{}

// StartAnalysis implements the AnalysisHandler interface
func (h *PHPSBOMAnalysisHandler) StartAnalysis(
	databases *ecosystem.PluginDatabases,
	dispatcherMessage types_amqp.DispatcherPluginMessage,
	config plugin_db.Plugin,
	analysisDoc codeclarity.Analysis,
) (map[string]any, codeclarity.AnalysisStatus, error) {
	return startAnalysis(databases, dispatcherMessage, config, analysisDoc)
}

// main is the entry point of the program.
func main() {
	pluginBase, err := ecosystem.NewPluginBase()
	if err != nil {
		log.Fatalf("Failed to initialize plugin base: %v", err)
	}
	defer pluginBase.Close()

	// Start the plugin with our analysis handler
	handler := &PHPSBOMAnalysisHandler{}
	err = pluginBase.Listen(handler)
	if err != nil {
		log.Fatalf("Failed to start plugin: %v", err)
	}
}

// startAnalysis is a function that performs the PHP SBOM analysis.
// It takes the following parameters:
// - args: Arguments for the analysis.
// - dispatcherMessage: DispatcherPluginMessage containing information about the analysis.
// - config: Plugin configuration.
// - analysis_document: Analysis document containing the analysis configuration.
// It returns a map[string]any containing the result of the analysis, the analysis status, and an error if any.
func startAnalysis(databases *ecosystem.PluginDatabases, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Get analysis config
	messageData := analysis_document.Config[config.Name].(map[string]any)

	// GET download path from ENV
	path := os.Getenv("DOWNLOAD_PATH")
	if path == "" {
		path = "/private" // Default path
	}

	// Destination folder - prepare the arguments for the plugin
	projectInterface, ok := messageData["project"]
	if !ok || projectInterface == nil {
		// Return failure if project path is not provided
		sbomOutput := types.Output{
			AnalysisInfo: types.AnalysisInfo{
				Status: codeclarity.FAILURE,
				Errors: []exceptions.Error{
					{
						Public:  exceptions.ErrorContent{Type: exceptions.GENERIC_ERROR, Description: "Project path not provided in analysis configuration"},
						Private: exceptions.ErrorContent{Type: "ProjectPathMissingException", Description: "The 'project' field is missing from the analysis configuration"},
					},
				},
			},
		}

		result := codeclarity.Result{
			Result:     types.ConvertOutputToMap(sbomOutput),
			AnalysisId: dispatcherMessage.AnalysisId,
			Plugin:     config.Name,
			CreatedOn:  time.Now(),
		}
		_, err := databases.Codeclarity.NewInsert().Model(&result).Exec(context.Background())
		if err != nil {
			panic(err)
		}

		return map[string]any{"sbomKey": result.Id}, codeclarity.FAILURE, nil
	}

	project := path + "/" + projectInterface.(string)

	// Debug logging
	log.Printf("PHP SBOM Debug - DOWNLOAD_PATH: %s", path)
	log.Printf("PHP SBOM Debug - project config: %s", projectInterface.(string))
	log.Printf("PHP SBOM Debug - full project path: %s", project)

	// Start the plugin
	sbomOutput := codeclarity_src.Start(project, analysis_document.Id, databases.Knowledge)

	// Convert output to map and store result
	result := codeclarity.Result{
		Result:     types.ConvertOutputToMap(sbomOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err := databases.Codeclarity.NewInsert().Model(&result).Exec(context.Background())
	if err != nil {
		return nil, codeclarity.FAILURE, fmt.Errorf("failed to save result: %w", err)
	}

	// Prepare the result to store in step
	// In this case we only store the sbomKey
	// The other plugins will use this key to get the sbom
	res := make(map[string]any)
	res["sbomKey"] = result.Id
	res["packageCount"] = getTotalDependencyCountFromOutput(sbomOutput)
	res["framework"] = sbomOutput.AnalysisInfo.Extra.Framework

	// The output is always a map[string]any
	return res, sbomOutput.AnalysisInfo.Status, nil
}

// getTotalDependencyCountFromOutput counts total dependencies from the output
func getTotalDependencyCountFromOutput(output types.Output) int {
	total := 0
	for _, ws := range output.WorkSpaces {
		total += len(ws.Dependencies)
	}
	return total
}
