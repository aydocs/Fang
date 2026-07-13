package xpath

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type XPathModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *XPathModule) ID() string                { return "xpath" }
func (m *XPathModule) Name() string              { return "XPath Injection Scanner" }
func (m *XPathModule) Description() string       { return "Detects XPath injection in XML-based queries" }
func (m *XPathModule) Severity() models.Severity { return models.High }

func (m *XPathModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *XPathModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	params := inject.TargetParams(target)

	errorMarkers := []string{"xpath", "xpath exception", "saxon", "msxsl", "xpath syntax", "xml"}

	for _, param := range params {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		baseline, _ := m.client.Get(inject.BuildTestURL(target.URL, param, "fang-baseline-xyz"))
		baselineBody := ""
		if baseline != nil {
			baselineBody = strings.ToLower(baseline.Body)
		}

		for _, pd := range inject.GenXPathPayloads() {
			testURL := inject.BuildTestURL(target.URL, param, pd.Value)
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil {
				continue
			}
			body := strings.ToLower(resp.Body)

			if pd.Check != "" && strings.Contains(body, strings.ToLower(pd.Check)) && !strings.Contains(baselineBody, strings.ToLower(pd.Check)) {
				findings = append(findings, m.finding(
					"XPath Injection - Reflection",
					models.High, models.MediumConfidence,
					testURL, param, pd.Value,
					fmt.Sprintf("Marker '%s' reflected, indicating XPath query manipulation", pd.Check),
					"Use parameterized XPath queries and escape single/double quotes and apostrophes.",
					"CWE-643",
					"",
				))
				goto nextParam
			}
			for _, em := range errorMarkers {
				if strings.Contains(body, em) {
					findings = append(findings, m.finding(
						"XPath Injection - Error Based",
						models.High, models.HighConfidence,
						testURL, param, pd.Value,
						fmt.Sprintf("XPath error signature detected: %s", em),
						"Validate XML/XPath inputs and avoid string-concatenated XPath expressions.",
						"CWE-643",
						"",
					))
					goto nextParam
				}
			}
		}
	nextParam:
	}
	return findings, nil
}

func (m *XPathModule) finding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
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
		ModuleID:    "xpath",
	}
}

func init() {
	engine.GetRegistry().Register(&XPathModule{})
}
