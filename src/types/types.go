package types

import (
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptions "github.com/CodeClarityCE/utility-types/exceptions"
)

type WorkspaceInfo struct {
	Info1 string
	Info2 map[string][]string
}

type AnalysisStatus string

const (
	SUCCESS AnalysisStatus = "success"
	FAILURE AnalysisStatus = "failure"
)

type AnalysisStats struct {
	AnyStat int `json:"anystat"`
}

type AnalysisInfo struct {
	Status            codeclarity.AnalysisStatus `json:"status"`
	Errors            []exceptions.Error         `json:"errors"`
	AnalysisStartTime string                     `json:"analysis_start_time"`
	AnalysisEndTime   string                     `json:"analysis_end_time"`
	AnalysisDeltaTime float64                    `json:"analysis_delta_time"`
	AnalysisStats     AnalysisStats              `json:"stats"`
}

type Output struct {
	WorkSpaces   map[string]WorkspaceInfo `json:"workspaces"`
	AnalysisInfo AnalysisInfo             `json:"analysis_info"`
}

type AnalysisStatLicenseSeverityDist map[string]int

func ConvertOutputToMap(output Output) map[string]interface{} {
	result := make(map[string]interface{})

	// Convert WorkSpaces to map
	workspaces := make(map[string]interface{})
	for key, value := range output.WorkSpaces {
		workspace := make(map[string]interface{})
		workspace["Info1"] = value.Info1
		workspace["Info2"] = value.Info2
		workspaces[key] = workspace
	}
	result["workspaces"] = workspaces

	// Convert AnalysisInfo to map
	analysisInfo := make(map[string]interface{})
	analysisInfo["status"] = output.AnalysisInfo.Status
	analysisInfo["errors"] = output.AnalysisInfo.Errors
	analysisInfo["analysis_start_time"] = output.AnalysisInfo.AnalysisStartTime
	analysisInfo["analysis_end_time"] = output.AnalysisInfo.AnalysisEndTime
	analysisInfo["analysis_delta_time"] = output.AnalysisInfo.AnalysisDeltaTime
	analysisInfo["stats"] = output.AnalysisInfo.AnalysisStats
	result["analysis_info"] = analysisInfo

	return result
}
