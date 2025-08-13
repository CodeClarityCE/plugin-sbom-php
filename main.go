package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	codeclarity_src "github.com/CodeClarityCE/plugin-php-sbom/src"
	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Define the arguments you want to pass to the callback function
type Arguments struct {
	codeclarity *bun.DB
	knowledge   *bun.DB
}

// main is the entry point of the program.
// It reads the configuration, initializes the necessary databases and graph,
// and starts listening on the queue.
func main() {
	config, err := readConfig()
	if err != nil {
		log.Printf("%v", err)
		return
	}

	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return
	}

	dsn_knowledge := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Results + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(50*time.Second)))
	db_codeclarity := bun.NewDB(sqldb, pgdialect.New())
	defer db_codeclarity.Close()

	args := Arguments{
		codeclarity: db_codeclarity,
		knowledge:   db_knowledge,
	}

	// Start listening on the queue
	amqp_helper.Listen("dispatcher_"+config.Name, callback, args, config)
}

// startAnalysis is a function that performs the PHP SBOM analysis.
// It takes the following parameters:
// - args: Arguments for the analysis.
// - dispatcherMessage: DispatcherPluginMessage containing information about the analysis.
// - config: Plugin configuration.
// - analysis_document: Analysis document containing the analysis configuration.
// It returns a map[string]any containing the result of the analysis, the analysis status, and an error if any.
func startAnalysis(args Arguments, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
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
		_, err := args.codeclarity.NewInsert().Model(&result).Exec(context.Background())
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
	sbomOutput := codeclarity_src.Start(project, analysis_document.Id, args.knowledge)

	// Convert output to map and store result
	result := codeclarity.Result{
		Result:     types.ConvertOutputToMap(sbomOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err := args.codeclarity.NewInsert().Model(&result).Exec(context.Background())
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
