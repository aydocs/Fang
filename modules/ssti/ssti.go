package ssti

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

type SSTIModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SSTIModule) ID() string   { return "ssti" }
func (m *SSTIModule) Name() string { return "Server-Side Template Injection Scanner" }
func (m *SSTIModule) Description() string {
	return "Detects SSTI in Jinja2, Twig, FreeMarker, and Velocity template engines"
}
func (m *SSTIModule) Severity() models.Severity { return models.Critical }

func (m *SSTIModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SSTIModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"name", "message", "content", "template", "page", "input", "text", "data", "q", "s"}
	}

	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		polyglotMath := "{{7*7}}${7*7}#{7*7}"
		polyglotURL := m.buildURL(parsed, params, paramName, polyglotMath)
		polyglotResp, err := m.client.Get(polyglotURL)
		if err != nil {
			continue
		}
		polyglotBody := polyglotResp.Body

		if strings.Contains(polyglotBody, "49") && !strings.Contains(baselineResp.Body, "49") {
			findings = append(findings, &models.Finding{
				Title:       "SSTI - Template Evaluation (Polyglot Math)",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         polyglotURL,
				Parameter:   paramName,
				Payload:     polyglotMath,
				Evidence:    "7*7 evaluated to 49 in response",
				Description: fmt.Sprintf("Parameter '%s' evaluates template expressions. The server processed {{7*7}}, ${7*7}, or #{7*7} as code.", paramName),
				Remediation: "Do not render user input in template engines. Use sandboxed template environments if necessary.",
				CWEID:       "CWE-1336",
				ModuleID:    "ssti",
			})
			continue
		}

		for _, jt := range inject.SSTIJinja2Payloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, jt.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, jt.Check) && !strings.Contains(baselineResp.Body, jt.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - Jinja2/Twig Template Engine",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     jt.Value,
					Evidence:    fmt.Sprintf("Template expression evaluated: %s", jt.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to Jinja2/Twig SSTI.", paramName),
					Remediation: "Disable template evaluation on user-controlled input. Use sandboxed templates.",
					CWEID:       "CWE-1336",
					ModuleID:    "ssti",
				})
				goto nextParam
			}
		}

		for _, ft := range inject.SSTIFreeMarkerPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, ft.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, ft.Check) && !strings.Contains(baselineResp.Body, ft.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - FreeMarker Template Engine",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     ft.Value,
					Evidence:    fmt.Sprintf("FreeMarker expression evaluated: %s", ft.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to FreeMarker SSTI.", paramName),
					Remediation: "Sanitize user input before template rendering. Use template sandboxing.",
					CWEID:       "CWE-1336",
					ModuleID:    "ssti",
				})
				goto nextParam
			}
		}

		for _, vt := range inject.SSTIVelocityPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, vt.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, vt.Check) && !strings.Contains(baselineResp.Body, vt.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - Velocity Template Engine",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     vt.Value,
					Evidence:    fmt.Sprintf("Velocity expression evaluated: %s", vt.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to Velocity SSTI.", paramName),
					Remediation: "Do not pass user input to Velocity templates. Use strict input validation.",
					CWEID:       "CWE-1336",
					ModuleID:    "ssti",
				})
				goto nextParam
			}
		}

		for _, ep := range inject.SSTIErrorPatterns() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, "{{")
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			if strings.Contains(respBody, strings.ToLower(ep)) && !strings.Contains(strings.ToLower(baselineResp.Body), strings.ToLower(ep)) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - Error Based Detection",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     "{{",
					Evidence:    fmt.Sprintf("Template error detected: %s", ep),
					Description: fmt.Sprintf("Parameter '%s' reveals template engine errors suggesting SSTI vulnerability.", paramName),
					Remediation: "Disable detailed error messages in production. Sanitize template inputs.",
					CWEID:       "CWE-1336",
					ModuleID:    "ssti",
				})
				break
			}
		}

	nextParam:
	}

	return findings, nil
}

func (m *SSTIModule) buildURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func init() {
	engine.GetRegistry().Register(&SSTIModule{})
}
