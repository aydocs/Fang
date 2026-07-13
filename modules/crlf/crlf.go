package crlf

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type CRLFModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *CRLFModule) ID() string   { return "crlf" }
func (m *CRLFModule) Name() string { return "CRLF Injection Scanner" }
func (m *CRLFModule) Description() string {
	return "Detects CRLF/HTTP header injection via response header manipulation"
}
func (m *CRLFModule) Severity() models.Severity { return models.High }

func (m *CRLFModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *CRLFModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	params := inject.TargetParams(target)

	encodings := []string{
		"%0d%0a", "%0a%0d", "%0d%0a%00", "%00%0d%0a",
		"\r\n", "\n\r", "%0d%0a",
	}

	for _, param := range params {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		marker := fmt.Sprintf("fang-crlf-%d", len(findings)+1)
		for _, enc := range encodings {
			injected := fmt.Sprintf("%sX-Fang-Injected: %s", enc, marker)
			testURL := inject.BuildTestURL(target.URL, param, url.QueryEscape(injected))
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil || resp.Headers == nil {
				continue
			}
			if hdr := resp.Headers.Get("X-Fang-Injected"); hdr != "" {
				findings = append(findings, m.finding(
					"CRLF / Header Injection",
					models.High, models.HighConfidence,
					testURL, param, injected,
					fmt.Sprintf("Injected header 'X-Fang-Injected: %s' reflected in response", hdr),
					"Reject CRLF sequences in user input.",
					"Use strict input validation and percent-encoding.",
					"CWE-93",
				))
				break
			}
		}
	}
	return findings, nil
}

func (m *CRLFModule) finding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
	return &models.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		URL:         urlStr,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: description,
		Remediation: remediation,
		CWEID:       cwe,
		ModuleID:    "crlf",
	}
}

func init() {
	engine.GetRegistry().Register(&CRLFModule{})
}
