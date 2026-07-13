package redirect

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

type RedirectModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *RedirectModule) ID() string   { return "redirect" }
func (m *RedirectModule) Name() string { return "Open Redirect Scanner" }
func (m *RedirectModule) Description() string {
	return "Detects open redirect via Location headers, meta refresh, and JavaScript redirects"
}
func (m *RedirectModule) Severity() models.Severity { return models.Medium }

func (m *RedirectModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *RedirectModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	redirectParams := inject.OpenRedirectParams()

	paramSet := make(map[string]bool)
	for k := range params {
		paramSet[k] = true
	}

	for _, rp := range redirectParams {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		evilURLs := inject.RedirectPayloads()

		for _, evil := range evilURLs {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}

			testURL := fmt.Sprintf("%s://%s%s?%s=%s", parsed.Scheme, parsed.Host, parsed.Path, rp, url.QueryEscape(evil))

			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.Redirect != "" {
				redirLower := strings.ToLower(resp.Redirect)
				evilLower := strings.ToLower(evil)

				if strings.Contains(redirLower, evilLower) {
					findings = append(findings, &models.Finding{
						Title:       "Open Redirect - Location Header",
						Severity:    models.Medium,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   rp,
						Payload:     evil,
						Evidence:    fmt.Sprintf("Redirect to: %s", resp.Redirect),
						Description: fmt.Sprintf("Parameter '%s' allows open redirect via Location header to arbitrary domains.", rp),
						Remediation: "Validate redirect URLs against a whitelist of allowed domains. Do not accept arbitrary redirect targets.",
						CWEID:       "CWE-601",
						ModuleID:    "redirect",
					})
					break
				}
			}

			respBody := resp.Body
			evilInBody := false

			if strings.Contains(respBody, "url="+evil) || strings.Contains(respBody, "URL="+evil) {
				evilInBody = true
				findings = append(findings, &models.Finding{
					Title:       "Open Redirect - Meta Refresh",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   rp,
					Payload:     evil,
					Evidence:    fmt.Sprintf("Meta refresh redirect to: %s", evil),
					Description: fmt.Sprintf("Parameter '%s' allows open redirect via meta refresh tag.", rp),
					Remediation: "Validate redirect URLs against a whitelist of allowed domains.",
					CWEID:       "CWE-601",
					ModuleID:    "redirect",
				})
			}

			if strings.Contains(respBody, "window.location") && strings.Contains(respBody, evil) {
				evilInBody = true
				findings = append(findings, &models.Finding{
					Title:       "Open Redirect - JavaScript",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   rp,
					Payload:     evil,
					Evidence:    fmt.Sprintf("JavaScript location redirect to: %s", evil),
					Description: fmt.Sprintf("Parameter '%s' allows open redirect via JavaScript window.location.", rp),
					Remediation: "Validate redirect URLs against a whitelist of allowed domains.",
					CWEID:       "CWE-601",
					ModuleID:    "redirect",
				})
			}

			if strings.Contains(respBody, "location.href") && strings.Contains(respBody, evil) {
				evilInBody = true
				findings = append(findings, &models.Finding{
					Title:       "Open Redirect - JavaScript (location.href)",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   rp,
					Payload:     evil,
					Evidence:    fmt.Sprintf("JavaScript location.href contains: %s", evil),
					Description: fmt.Sprintf("Parameter '%s' allows open redirect via JavaScript location.href.", rp),
					Remediation: "Validate redirect URLs against a whitelist of allowed domains.",
					CWEID:       "CWE-601",
					ModuleID:    "redirect",
				})
			}

			if evilInBody {
				break
			}
		}
	}

	for paramName := range paramSet {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, evil := range []string{"//evil.fangtest.com/phish", "https://evil.fangtest.com"} {
			testURL := fmt.Sprintf("%s://%s%s?%s=%s", parsed.Scheme, parsed.Host, parsed.Path, paramName, url.QueryEscape(evil))
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.Redirect != "" && strings.Contains(strings.ToLower(resp.Redirect), "evil.fangtest.com") {
				findings = append(findings, &models.Finding{
					Title:       "Open Redirect - Existing Parameter",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     evil,
					Evidence:    fmt.Sprintf("Redirect to: %s", resp.Redirect),
					Description: fmt.Sprintf("Existing parameter '%s' is vulnerable to open redirect.", paramName),
					Remediation: "Validate redirect URLs against a whitelist of allowed domains.",
					CWEID:       "CWE-601",
					ModuleID:    "redirect",
				})
				break
			}
		}
	}

	return findings, nil
}

func init() {
	engine.GetRegistry().Register(&RedirectModule{})
}
