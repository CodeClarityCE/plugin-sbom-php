package main

import (
	"context"
	"database/sql"
	"log"
	"os"

	output "github.com/CodeClarityCE/plugin-template/src/types"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
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
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Results + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db_codeclarity := bun.NewDB(sqldb, pgdialect.New())
	defer db_codeclarity.Close()

	args := Arguments{
		codeclarity: db_codeclarity,
		knowledge:   db_knowledge,
	}

	// Start listening on the queue
	amqp_helper.Listen("dispatcher_"+config.Name, callback, args, config)
}

func startAnalysis(args Arguments, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Prepare the arguments for the plugin
	// Get previous stage
	analysis_stage := analysis_document.Stage - 1
	// Get sbomKey from previous stage
	sbomKey := uuid.UUID{}
	for _, step := range analysis_document.Steps[analysis_stage] {
		if step.Name == "js-sbom" {
			sbomKeyUUID, err := uuid.Parse(step.Result["sbomKey"].(string))
			if err != nil {
				panic(err)
			}
			sbomKey = sbomKeyUUID
			break
		}
	}

	var vulnOutput output.Output
	// start := time.Now()

	res := codeclarity.Result{
		Id: sbomKey,
	}
	err := args.codeclarity.NewSelect().Model(&res).Where("id = ?", sbomKey).Scan(context.Background())
	if err != nil {
		panic(err)
	}
	// sbom := sbom.Output{}
	// err = json.Unmarshal(res.Result.([]byte), &sbom)
	// if err != nil {
	// 	exceptionManager.AddError(
	// 		"", exceptions.GENERIC_ERROR,
	// 		fmt.Sprintf("Error when reading sbom output: %s", err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
	// 	)
	// 	// return outputGenerator.FailureOutput(nil, start)
	// 	vulnOutput = outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	// } else {
	// 	vulnOutput = vulnerabilities.Start(sbom, "JS", start, args.knowledge)
	// }

	vuln_result := codeclarity.Result{
		Result:     output.ConvertOutputToMap(vulnOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
	}
	_, err = args.codeclarity.NewInsert().Model(&vuln_result).Exec(context.Background())
	if err != nil {
		panic(err)
	}

	// Prepare the result to store in step
	// In this case we only store the sbomKey
	// The other plugins will use this key to get the sbom
	result := make(map[string]any)
	result["vulnKey"] = vuln_result.Id

	// The output is always a map[string]any
	return result, vulnOutput.AnalysisInfo.Status, nil
}
