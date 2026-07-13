package xxe

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type XXEModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *XXEModule) ID() string   { return "xxe" }
func (m *XXEModule) Name() string { return "XML External Entity Scanner" }
func (m *XXEModule) Description() string {
	return "Detects XXE via classic file reading, blind OOB, SOAP, and JSON-to-XML converters"
}
func (m *XXEModule) Severity() models.Severity { return models.Critical }

func (m *XXEModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *XXEModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	for _, cp := range inject.XXEClassicPayloads() {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		resp, err := m.client.DoRaw("POST", target.URL, map[string]string{"Content-Type": "application/xml"}, cp.Payload)
		if err != nil {
			continue
		}

		if cp.Check != "" && strings.Contains(resp.Body, cp.Check) {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("XXE - %s", cp.Name),
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Payload:     truncate(cp.Payload, 80),
				Evidence:    fmt.Sprintf("File content '%s' found in response", cp.Check),
				Description: "The XML parser processes external entities, allowing local file reads.",
				Remediation: "Disable external entity processing (DOCTYPE and ENTITY) in XML parsers.",
				CWEID:       "CWE-611",
				ModuleID:    "xxe",
			})
			goto blindCheck
		}

		if resp.StatusCode != 400 && resp.StatusCode != 500 {
			respBody := strings.ToLower(resp.Body)
			if strings.Contains(respBody, "xml") || strings.Contains(respBody, "entity") || strings.Contains(respBody, "doctype") {
				if cp.Check == "" {
					findings = append(findings, &models.Finding{
						Title:       "XXE - Possible (Blind SSRF)",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         target.URL,
						Payload:     truncate(cp.Payload, 80),
						Evidence:    "XML processing accepted with external entity reference",
						Description: "The application may be processing external entity references. Verify with OOB techniques.",
						Remediation: "Disable external entity processing in XML parsers.",
						CWEID:       "CWE-611",
						ModuleID:    "xxe",
					})
					goto blindCheck
				}
			}
		}
	}

blindCheck:
	for _, sp := range inject.XXESOAPPayloads() {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		soapEndpoints := []string{"/soap", "/ws", "/wsdl", "/api/soap", "/service", "/soap.php", "/soap.aspx", "/api/ws"}
		for _, endpoint := range soapEndpoints {
			testURL := target.URL + endpoint

			resp, err := m.client.DoRaw("POST", testURL, map[string]string{"Content-Type": "text/xml"}, sp.Payload)
			if err != nil {
				continue
			}

			if sp.Check != "" && strings.Contains(resp.Body, sp.Check) {
				findings = append(findings, &models.Finding{
					Title:       "XXE - SOAP Endpoint",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Payload:     truncate(sp.Payload, 80),
					Evidence:    "SOAP endpoint processes external entities",
					Description: "SOAP endpoint at " + endpoint + " is vulnerable to XXE injection.",
					Remediation: "Disable external entity processing in SOAP XML parsers.",
					CWEID:       "CWE-611",
					ModuleID:    "xxe",
				})
				goto jsonCheck
			}
		}
	}

jsonCheck:
	for _, jp := range inject.XXEJSONPayloads() {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		resp, err := m.client.DoRaw("POST", target.URL, map[string]string{"Content-Type": "application/json"}, jp.Payload)
		if err != nil {
			continue
		}

		if jp.Check != "" && strings.Contains(resp.Body, jp.Check) {
			findings = append(findings, &models.Finding{
				Title:       "XXE - JSON-to-XML Converter",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Payload:     truncate(jp.Payload, 100),
				Evidence:    "JSON input that was converted to XML processes external entities",
				Description: "The JSON-to-XML converter is vulnerable to XXE injection via embedded XML.",
				Remediation: "Disable external entity processing in the XML conversion layer.",
				CWEID:       "CWE-611",
				ModuleID:    "xxe",
			})
			break
		}
	}

	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func init() {
	engine.GetRegistry().Register(&XXEModule{})
}
