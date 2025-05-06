package outputGenerator

import (
	"time"

	types "github.com/CodeClarityCE/plugin-template/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
)

// getAnalysisTiming calculates the analysis timing by measuring the elapsed time between the start time and the current time.
// It returns the start time, end time, and elapsed time in seconds.
func getAnalysisTiming(start time.Time) (string, string, float64) {
	end := time.Now()
	elapsed := time.Since(start)
	return start.Local().String(), end.Local().String(), elapsed.Seconds()
}

// SuccessOutput generates the success output for the license analysis.
// It takes in the workspaceData, analysisStats, sbomAnalysisInfo, and start time as parameters.
// It returns an instance of types.Output containing the workspace data, analysis information, and timing details.
func SuccessOutput(workspaceData map[string]types.WorkspaceInfo, analysisStats types.AnalysisStats, sbomAnalysisInfo types.AnalysisInfo, start time.Time) types.Output {
	output := types.Output{}
	output.WorkSpaces = workspaceData
	output.AnalysisInfo = types.AnalysisInfo{}
	output.AnalysisInfo.Status = codeclarity.SUCCESS
	formattedStart, formattedEnd, delta := getAnalysisTiming(start)
	output.AnalysisInfo.AnalysisStartTime = formattedStart
	output.AnalysisInfo.AnalysisEndTime = formattedEnd
	output.AnalysisInfo.AnalysisDeltaTime = delta
	output.AnalysisInfo.Errors = exceptionManager.GetErrors()
	output.AnalysisInfo.AnalysisStats = analysisStats
	return output
}

// FailureOutput generates an output object for a failed analysis.
// It takes the sbomAnalysisInfo pointer and the start time as parameters.
// It returns an output object with the analysis status set to FAILURE.
// The output object includes workspace data, analysis information, and error details.
func FailureOutput(sbomAnalysisInfo types.AnalysisInfo, start time.Time) types.Output {
	output := types.Output{}
	output.AnalysisInfo.Status = codeclarity.FAILURE
	workspaceData := map[string]types.WorkspaceInfo{}
	output.WorkSpaces = workspaceData
	output.AnalysisInfo = types.AnalysisInfo{}
	output.AnalysisInfo.Status = codeclarity.FAILURE
	formattedStart, formattedEnd, delta := getAnalysisTiming(start)
	output.AnalysisInfo.AnalysisStartTime = formattedStart
	output.AnalysisInfo.AnalysisEndTime = formattedEnd
	output.AnalysisInfo.AnalysisDeltaTime = delta
	output.AnalysisInfo.Errors = exceptionManager.GetErrors()

	return output
}

// GenerateAnalysisStats calculates the analysis statistics based on the provided workspace data.
// It takes a map of workspace data, where the keys are workspace names and the values are pointers to WorkSpaceLicenseInfoInternal structs.
// The function iterates over the workspace data and counts the number of SPDX licenses, non-SPDX licenses, copy left licenses, and permissive licenses.
// It also generates a distribution map of licenses, where the keys are license names and the values are the number of occurrences.
// The function returns an AnalysisStats struct containing the calculated statistics.
func GenerateAnalysisStats(workspaceData map[string]types.WorkspaceInfo) types.AnalysisStats {

	// TODO Complete here
	return types.AnalysisStats{
		AnyStat: 0,
	}

}
