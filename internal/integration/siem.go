package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type SIEMType string

const (
	SIEMSplunk   SIEMType = "splunk"
	SIEMELK      SIEMType = "elastic"
	SIEMQRadar   SIEMType = "qradar"
	SIEMSentinel SIEMType = "sentinel"
)

type SIEMConfig struct {
	Type  SIEMType `json:"type"`
	URL   string   `json:"url"`
	Token string   `json:"token"`
	Index string   `json:"index"`
}

type SIEMClient struct {
	config *SIEMConfig
	client *http.Client
}

func NewSIEMClient(cfg *SIEMConfig) *SIEMClient {
	return &SIEMClient{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SIEMClient) SendFinding(ctx context.Context, finding *models.Finding, targetURL string) error {
	switch s.config.Type {
	case SIEMSplunk:
		return s.sendSplunk(ctx, finding, targetURL)
	case SIEMELK:
		return s.sendELK(ctx, finding, targetURL)
	case SIEMQRadar:
		return s.sendQRadar(ctx, finding, targetURL)
	case SIEMSentinel:
		return s.sendSentinel(ctx, finding, targetURL)
	default:
		return fmt.Errorf("unsupported siem type: %s", s.config.Type)
	}
}

func (s *SIEMClient) SendScanResult(ctx context.Context, result *models.ScanResult) error {
	switch s.config.Type {
	case SIEMSplunk:
		return s.sendSplunkResult(ctx, result)
	case SIEMELK:
		return s.sendELKResult(ctx, result)
	case SIEMQRadar:
		return s.sendQRadarResult(ctx, result)
	case SIEMSentinel:
		return s.sendSentinelResult(ctx, result)
	default:
		return fmt.Errorf("unsupported siem type: %s", s.config.Type)
	}
}

func (s *SIEMClient) SendEvent(ctx context.Context, eventType string, data map[string]interface{}) error {
	event := map[string]interface{}{
		"event":     eventType,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"source":    "fang",
		"data":      data,
	}

	switch s.config.Type {
	case SIEMSplunk:
		return s.sendJSON(ctx, "/services/collector", map[string]interface{}{
			"event": event,
			"index": s.config.Index,
		})
	case SIEMELK:
		return s.sendJSON(ctx, fmt.Sprintf("/%s/_doc", s.config.Index), event)
	case SIEMQRadar:
		return s.sendCEF(ctx, eventType, data)
	case SIEMSentinel:
		return s.sendJSON(ctx, "/api/logs", map[string]interface{}{
			"logs": []interface{}{event},
		})
	default:
		return fmt.Errorf("unsupported siem type: %s", s.config.Type)
	}
}

func (s *SIEMClient) sendSplunk(ctx context.Context, finding *models.Finding, targetURL string) error {
	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"type":        "finding",
			"title":       finding.Title,
			"severity":    finding.Severity.String(),
			"confidence":  finding.Confidence.String(),
			"target":      targetURL,
			"url":         finding.URL,
			"parameter":   finding.Parameter,
			"payload":     finding.Payload,
			"evidence":    finding.Evidence,
			"description": finding.Description,
			"remediation": finding.Remediation,
			"cwe_id":      finding.CWEID,
			"module_id":   finding.ModuleID,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
			"source":      "fang",
		},
		"index": s.config.Index,
	}
	return s.sendJSON(ctx, "/services/collector", payload)
}

func (s *SIEMClient) sendSplunkResult(ctx context.Context, result *models.ScanResult) error {
	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"type":      "scan_result",
			"target":    result.Target,
			"findings":  result.Findings,
			"summary":   result.Summary,
			"start":     result.StartTime,
			"end":       result.EndTime,
			"duration":  result.Duration,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"source":    "fang",
		},
		"index": s.config.Index,
	}
	return s.sendJSON(ctx, "/services/collector", payload)
}

func (s *SIEMClient) sendELK(ctx context.Context, finding *models.Finding, targetURL string) error {
	doc := map[string]interface{}{
		"@timestamp":  time.Now().UTC().Format(time.RFC3339),
		"type":        "finding",
		"title":       finding.Title,
		"severity":    finding.Severity.String(),
		"confidence":  finding.Confidence.String(),
		"target":      targetURL,
		"url":         finding.URL,
		"parameter":   finding.Parameter,
		"payload":     finding.Payload,
		"evidence":    finding.Evidence,
		"description": finding.Description,
		"remediation": finding.Remediation,
		"cwe_id":      finding.CWEID,
		"module_id":   finding.ModuleID,
		"source":      "fang",
	}
	return s.sendJSON(ctx, fmt.Sprintf("/%s/_doc", s.config.Index), doc)
}

func (s *SIEMClient) sendELKResult(ctx context.Context, result *models.ScanResult) error {
	doc := map[string]interface{}{
		"@timestamp": time.Now().UTC().Format(time.RFC3339),
		"type":       "scan_result",
		"target":     result.Target,
		"total":      result.Summary.Total,
		"critical":   result.Summary.Critical,
		"high":       result.Summary.High,
		"medium":     result.Summary.Medium,
		"low":        result.Summary.Low,
		"info":       result.Summary.Info,
		"findings":   result.Findings,
		"start_time": result.StartTime,
		"end_time":   result.EndTime,
		"duration":   result.Duration,
		"source":     "fang",
	}
	return s.sendJSON(ctx, fmt.Sprintf("/%s/_doc", s.config.Index), doc)
}

func (s *SIEMClient) sendQRadar(ctx context.Context, finding *models.Finding, targetURL string) error {
	return s.sendCEF(ctx, "finding", map[string]interface{}{
		"title":       finding.Title,
		"severity":    finding.Severity.String(),
		"confidence":  finding.Confidence.String(),
		"target":      targetURL,
		"url":         finding.URL,
		"parameter":   finding.Parameter,
		"payload":     finding.Payload,
		"cwe_id":      finding.CWEID,
		"module_id":   finding.ModuleID,
		"description": finding.Description,
	})
}

func (s *SIEMClient) sendQRadarResult(ctx context.Context, result *models.ScanResult) error {
	return s.sendCEF(ctx, "scan_result", map[string]interface{}{
		"target":   result.Target,
		"total":    fmt.Sprintf("%d", result.Summary.Total),
		"critical": fmt.Sprintf("%d", result.Summary.Critical),
		"high":     fmt.Sprintf("%d", result.Summary.High),
		"medium":   fmt.Sprintf("%d", result.Summary.Medium),
		"low":      fmt.Sprintf("%d", result.Summary.Low),
		"duration": result.Duration,
	})
}

func (s *SIEMClient) sendSentinel(ctx context.Context, finding *models.Finding, targetURL string) error {
	doc := map[string]interface{}{
		"TimeGenerated": time.Now().UTC().Format(time.RFC3339),
		"EventType":     "Finding",
		"Title":         finding.Title,
		"Severity":      finding.Severity.String(),
		"Confidence":    finding.Confidence.String(),
		"Target":        targetURL,
		"URL":           finding.URL,
		"Parameter":     finding.Parameter,
		"Payload":       finding.Payload,
		"Evidence":      finding.Evidence,
		"Description":   finding.Description,
		"Remediation":   finding.Remediation,
		"CWE":           finding.CWEID,
		"Module":        finding.ModuleID,
		"Source":        "Fang",
	}
	return s.sendJSON(ctx, "/api/logs", map[string]interface{}{
		"logs": []interface{}{doc},
	})
}

func (s *SIEMClient) sendSentinelResult(ctx context.Context, result *models.ScanResult) error {
	doc := map[string]interface{}{
		"TimeGenerated": time.Now().UTC().Format(time.RFC3339),
		"EventType":     "ScanResult",
		"Target":        result.Target,
		"Total":         result.Summary.Total,
		"Critical":      result.Summary.Critical,
		"High":          result.Summary.High,
		"Medium":        result.Summary.Medium,
		"Low":           result.Summary.Low,
		"Info":          result.Summary.Info,
		"Duration":      result.Duration,
		"Source":        "Fang",
	}
	return s.sendJSON(ctx, "/api/logs", map[string]interface{}{
		"logs": []interface{}{doc},
	})
}

func (s *SIEMClient) sendJSON(ctx context.Context, path string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := s.config.URL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if s.config.Token != "" {
		switch s.config.Type {
		case SIEMSplunk:
			req.Header.Set("Authorization", "Splunk "+s.config.Token)
		case SIEMELK:
			req.Header.Set("Authorization", "ApiKey "+s.config.Token)
		default:
			req.Header.Set("Authorization", "Bearer "+s.config.Token)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("siem returned status %d", resp.StatusCode)
	}

	return nil
}

func (s *SIEMClient) sendCEF(ctx context.Context, eventType string, data map[string]interface{}) error {
	sev := 5
	if v, ok := data["severity"]; ok {
		switch v.(string) {
		case "CRITICAL":
			sev = 10
		case "HIGH":
			sev = 8
		case "MEDIUM":
			sev = 5
		case "LOW":
			sev = 3
		case "INFO":
			sev = 1
		}
	}

	cef := fmt.Sprintf("CEF:0|Fang|SecurityScanner|1.0|%s|%s|%d|", eventType, getString(data, "title"), sev)

	var extensions string
	for k, v := range data {
		if k == "severity" || k == "title" {
			continue
		}
		extensions += fmt.Sprintf("%s=%s ", k, fmt.Sprintf("%v", v))
	}
	if extensions != "" {
		cef += extensions[:len(extensions)-1]
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL, bytes.NewReader([]byte(cef)))
	if err != nil {
		return fmt.Errorf("create cef request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.Token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send cef: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func getString(data map[string]interface{}, key string) string {
	if v, ok := data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return key
}
