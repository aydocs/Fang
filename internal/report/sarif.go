package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties sarifProperties `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifProperties struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
	CWEID      string `json:"cweId,omitempty"`
	ModuleID   string `json:"moduleId,omitempty"`
}

func sarifLevel(severity models.Severity) string {
	switch severity {
	case models.Critical, models.High:
		return "error"
	case models.Medium:
		return "warning"
	default:
		return "note"
	}
}

func generateSARIF(result *models.ScanResult) (string, error) {
	log := sarifLog{
		Schema:  "https://sarifweb.azurewebsites.net/schemas/2.1.0/sarif-json-schema.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Fang",
						Version:        "1.0.0",
						InformationURI: "https://github.com/aydocs/fang",
					},
				},
				Results: make([]sarifResult, 0, len(result.Findings)),
			},
		},
	}

	for _, f := range result.Findings {
		ruleID := f.CWEID
		if ruleID == "" {
			ruleID = f.ModuleID
		}
		if ruleID == "" {
			ruleID = strings.ToUpper(strings.ReplaceAll(f.Title, " ", "_"))
		}

		msg := f.Title
		if f.Description != "" {
			msg = f.Title + " - " + f.Description
		}

		r := sarifResult{
			RuleID: ruleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{
				Text: msg,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.URL,
						},
					},
				},
			},
			Properties: sarifProperties{
				Severity:   f.Severity.String(),
				Confidence: f.Confidence.String(),
				Evidence:   f.Evidence,
				CWEID:      f.CWEID,
				ModuleID:   f.ModuleID,
			},
		}

		log.Runs[0].Results = append(log.Runs[0].Results, r)
	}

	data := map[string]interface{}{
		"$schema": log.Schema,
		"version": log.Version,
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "Fang",
						"version":        "1.0.0",
						"informationUri": "https://github.com/aydocs/fang",
					},
				},
				"results": log.Runs[0].Results,
				"invocations": []map[string]interface{}{
					{
						"executionSuccessful": true,
						"startTimeUtc":        result.StartTime.UTC().Format(time.RFC3339),
						"endTimeUtc":          result.EndTime.UTC().Format(time.RFC3339),
					},
				},
				"properties": map[string]interface{}{
					"target":   result.Target,
					"duration": result.Duration,
					"total":    result.Summary.Total,
					"critical": result.Summary.Critical,
					"high":     result.Summary.High,
					"medium":   result.Summary.Medium,
					"low":      result.Summary.Low,
					"info":     result.Summary.Info,
				},
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("sarif marshal: %w", err)
	}

	return string(jsonBytes), nil
}
