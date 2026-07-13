package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

func generateJSON(result *models.ScanResult) (string, error) {
	data := map[string]interface{}{
		"tool":      "Fang",
		"version":   "1.0.0",
		"target":    result.Target,
		"startTime": result.StartTime.Format(time.RFC3339),
		"endTime":   result.EndTime.Format(time.RFC3339),
		"duration":  result.Duration,
		"summary": map[string]int{
			"total":    result.Summary.Total,
			"critical": result.Summary.Critical,
			"high":     result.Summary.High,
			"medium":   result.Summary.Medium,
			"low":      result.Summary.Low,
			"info":     result.Summary.Info,
		},
		"findings": result.Findings,
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}

	return string(jsonBytes), nil
}
