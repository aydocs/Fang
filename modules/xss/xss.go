package xss

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

type XSSModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *XSSModule) ID() string   { return "xss" }
func (m *XSSModule) Name() string { return "Cross-Site Scripting Scanner" }
func (m *XSSModule) Description() string {
	return "Detects reflected, stored, DOM-based, polyglot, and blind XSS vulnerabilities"
}
func (m *XSSModule) Severity() models.Severity { return models.High }

func (m *XSSModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *XSSModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
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
		paramNames = []string{"q", "search", "query", "input", "text", "name", "comment", "message", "page", "s"}
	}

	for _, paramName := range paramNames {
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

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		marker := inject.UniqueMarker("XSS")
		markerURL := m.buildURL(parsed, params, paramName, marker)
		markerResp, err := m.client.Get(markerURL)
		if err != nil {
			continue
		}

		isReflected := !strings.Contains(baselineResp.Body, marker) && strings.Contains(markerResp.Body, marker)

		if isReflected {
			findings = append(findings, &models.Finding{
				Title:       "XSS - Potential Reflection Point",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         markerURL,
				Parameter:   paramName,
				Payload:     marker,
				Evidence:    "Unique marker reflected in response body",
				Description: fmt.Sprintf("Parameter '%s' reflects user input in the response. This may be exploitable for XSS.", paramName),
				Remediation: "Implement input validation, output encoding, and Content-Security-Policy headers.",
				CWEID:       "CWE-79",
				ModuleID:    "xss",
			})
		}

		for _, xp := range inject.XSSPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, xp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, xp.Check) {
				if m.isEncoded(resp.Body, xp.Check) {
					continue
				}

				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("XSS - %s", xp.Name),
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     xp.Value,
					Evidence:    fmt.Sprintf("Payload reflected unencoded: %s", xp.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to reflected XSS with %s payload.", paramName, xp.Name),
					Remediation: "Implement context-aware output encoding. Use CSP headers. Validate and sanitize all user input.",
					CWEID:       "CWE-79",
					ModuleID:    "xss",
				})
				break
			}
		}

		for _, cp := range inject.XSSContextualPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, cp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, cp.Check) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("XSS - Contextual (%s context)", cp.Context),
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     cp.Value,
					Evidence:    fmt.Sprintf("%s context XSS payload reflected", cp.Context),
					Description: fmt.Sprintf("Parameter '%s' reflects input in %s context, allowing context-specific XSS.", paramName, cp.Context),
					Remediation: "Use context-appropriate output encoding. Never trust user input in script/attribute contexts.",
					CWEID:       "CWE-79",
					ModuleID:    "xss",
				})
			}
		}

		for _, bp := range inject.XSSBlindPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, bp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, bp.Check) {
				findings = append(findings, &models.Finding{
					Title:       "XSS - Blind / Stored",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     bp.Value,
					Evidence:    "Blind XSS callback marker found in response",
					Description: fmt.Sprintf("Parameter '%s' may be vulnerable to stored/blind XSS. The payload persists in the application.", paramName),
					Remediation: "Implement input validation and output encoding. Use CSP with report-uri for monitoring.",
					CWEID:       "CWE-79",
					ModuleID:    "xss",
				})
			}
		}
	}

	findings = append(findings, m.checkStoredXSS(ctx, target, paramNames)...)
	findings = append(findings, m.checkPOSTXSS(ctx, target, paramNames)...)

	return findings, nil
}

func (m *XSSModule) checkStoredXSS(ctx context.Context, target *models.Target, paramNames []string) []*models.Finding {
	var findings []*models.Finding

	marker := inject.UniqueMarker("STORED")
	for _, param := range paramNames {
		body := fmt.Sprintf("%s=<script>%%3C/script>%%3E%s%%3C/script%%3E", param, marker)
		resp, err := m.client.Post(target.URL, body)
		if err != nil {
			continue
		}
		_ = resp

		getResp, err := m.client.Get(target.URL)
		if err != nil {
			continue
		}

		if strings.Contains(getResp.Body, marker) {
			findings = append(findings, &models.Finding{
				Title:       "XSS - Stored (Persistent)",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Parameter:   param,
				Payload:     fmt.Sprintf("<script>%s</script>", marker),
				Evidence:    "Payload persisted and returned in subsequent requests",
				Description: fmt.Sprintf("Parameter '%s' is vulnerable to stored XSS. Payload persists across requests.", param),
				Remediation: "Implement input validation and output encoding on stored data. Use CSP headers.",
				CWEID:       "CWE-79",
				ModuleID:    "xss",
			})
		}
	}

	return findings
}

func (m *XSSModule) checkPOSTXSS(ctx context.Context, target *models.Target, paramNames []string) []*models.Finding {
	var findings []*models.Finding

	marker := inject.UniqueMarker("POSTX")
	for _, param := range paramNames {
		body := fmt.Sprintf("%s=<img src=x onerror=\"%s\">", param, marker)
		resp, err := m.client.Post(target.URL, body)
		if err != nil {
			continue
		}

		if strings.Contains(resp.Body, marker) {
			findings = append(findings, &models.Finding{
				Title:       "XSS - POST Based Reflected",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Parameter:   param,
				Payload:     fmt.Sprintf("<img src=x onerror=\"%s\">", marker),
				Evidence:    "POST request reflects XSS payload in response",
				Description: fmt.Sprintf("Parameter '%s' is vulnerable to reflected XSS via POST requests.", param),
				Remediation: "Implement input validation and output encoding for all HTTP methods.",
				CWEID:       "CWE-79",
				ModuleID:    "xss",
			})
		}
	}

	return findings
}

func (m *XSSModule) isEncoded(body, check string) bool {
	encodings := []string{
		"&lt;", "&gt;", "&amp;", "&quot;",
		"&#60;", "&#62;", "&#34;",
		`\u003c`, `\u003e`,
		url.QueryEscape(check),
	}
	for _, enc := range encodings {
		if strings.Contains(body, enc) {
			return true
		}
	}
	return false
}

func (m *XSSModule) buildURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func init() {
	engine.GetRegistry().Register(&XSSModule{})
}
