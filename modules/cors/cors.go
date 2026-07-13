package cors

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type CORSModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *CORSModule) ID() string   { return "cors" }
func (m *CORSModule) Name() string { return "CORS Misconfiguration Scanner" }
func (m *CORSModule) Description() string {
	return "Detects CORS misconfigurations including origin reflection, null origin, and wildcard with credentials"
}
func (m *CORSModule) Severity() models.Severity { return models.Medium }

func (m *CORSModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *CORSModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	domain := parsed.Hostname()

	originTests := inject.CORSOrigins()

	for _, ot := range originTests {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		var testOrigin string
		switch ot.Name {
		case "Similar Domain":
			testOrigin = "https://evil-" + domain
		case "HTTP Variant":
			testOrigin = "http://" + domain
		case "Subdomain Prefix":
			testOrigin = "https://" + domain + ".evil.com"
		default:
			testOrigin = ot.Origin
		}

		if testOrigin == "" {
			continue
		}

		resp, err := m.client.DoRaw("GET", target.URL, map[string]string{"Origin": testOrigin}, "")
		if err != nil {
			continue
		}

		acao := resp.Headers.Get("Access-Control-Allow-Origin")
		acac := resp.Headers.Get("Access-Control-Allow-Credentials")

		if acao == "" {
			continue
		}

		if acao == "*" && acac == "true" {
			findings = append(findings, &models.Finding{
				Title:       "CORS - Wildcard with Credentials",
				Severity:    models.Critical,
				Confidence:  models.CriticalConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
				Description: "CORS configuration allows wildcard origin (*) with Access-Control-Allow-Credentials: true. This allows any website to make authenticated cross-origin requests.",
				Remediation: "Remove wildcard origin when using credentials. Whitelist specific origins instead.",
				CWEID:       "CWE-942",
				ModuleID:    "cors",
			})
			continue
		}

		if acao == "*" {
			findings = append(findings, &models.Finding{
				Title:       "CORS - Wildcard Origin",
				Severity:    models.Medium,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("ACAO: %s", acao),
				Description: "CORS allows all origins via wildcard (*). This allows any website to read cross-origin responses.",
				Remediation: "Restrict Access-Control-Allow-Origin to specific trusted origins only.",
				CWEID:       "CWE-942",
				ModuleID:    "cors",
			})
			continue
		}

		if strings.Contains(acao, testOrigin) || (testOrigin == "null" && acao == "null") {
			severity := models.High
			switch ot.Name {
			case "Similar Domain":
				severity = models.Medium
			case "File Protocol":
				severity = models.Medium
			}

			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("CORS - %s", ot.Name),
				Severity:    severity,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Payload:     testOrigin,
				Evidence:    fmt.Sprintf("Origin: %s -> ACAO: %s, ACAC: %s", testOrigin, acao, acac),
				Description: fmt.Sprintf("CORS reflects the '%s' origin, which allows cross-origin access from untrusted sources.", ot.Name),
				Remediation: "Validate Origin header server-side against a whitelist. Do not reflect arbitrary origins.",
				CWEID:       "CWE-942",
				ModuleID:    "cors",
			})
		}
	}

	preflightOrigins := []string{"https://evil.fangtest.com", "null", "http://" + domain}
	for _, po := range preflightOrigins {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		resp, err := m.client.DoRaw("OPTIONS", target.URL, map[string]string{
			"Origin":                        po,
			"Access-Control-Request-Method": "GET",
		}, "")
		if err != nil {
			continue
		}

		acao := resp.Headers.Get("Access-Control-Allow-Origin")
		if acao != "" && acao != "*" && strings.Contains(acao, po) {
			findings = append(findings, &models.Finding{
				Title:       "CORS - Preflight Origin Reflection",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Payload:     po,
				Evidence:    fmt.Sprintf("OPTIONS %s -> ACAO: %s", po, acao),
				Description: "CORS preflight request reflects arbitrary origin in Access-Control-Allow-Origin header.",
				Remediation: "Validate origin in preflight responses. Do not reflect unvalidated origins.",
				CWEID:       "CWE-942",
				ModuleID:    "cors",
			})
		}
	}

	return findings, nil
}

func init() {
	engine.GetRegistry().Register(&CORSModule{})
}
