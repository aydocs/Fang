package headers

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type HeadersModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *HeadersModule) ID() string   { return "headers" }
func (m *HeadersModule) Name() string { return "Security Headers Analyzer" }
func (m *HeadersModule) Description() string {
	return "Passively analyzes security headers, cookie security, and server information disclosure"
}
func (m *HeadersModule) Severity() models.Severity { return models.Info }

func (m *HeadersModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *HeadersModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil, err
	}

	for _, sc := range inject.SecurityHeaders {
		value := resp.Headers.Get(sc.Name)
		if value == "" {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Missing Security Header: %s", sc.Name),
				Severity:    models.Severity(sc.Severity),
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Description: fmt.Sprintf("The '%s' security header is missing from HTTP responses.", sc.Name),
				Remediation: sc.Fix,
				CWEID:       sc.CWE,
				ModuleID:    "headers",
			})
		} else {
			if sc.Name == "Strict-Transport-Security" {
				if !strings.Contains(value, "max-age=") {
					findings = append(findings, &models.Finding{
						Title:       "HSTS Missing max-age Directive",
						Severity:    models.Medium,
						Confidence:  models.HighConfidence,
						URL:         target.URL,
						Evidence:    fmt.Sprintf("HSTS: %s", value),
						Description: "Strict-Transport-Security header is missing the required max-age directive.",
						Remediation: "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
						CWEID:       "CWE-523",
						ModuleID:    "headers",
					})
				}
				if !strings.Contains(value, "includeSubDomains") && !strings.Contains(strings.ToLower(value), "includesubdomains") {
					findings = append(findings, &models.Finding{
						Title:       "HSTS Missing includeSubDomains",
						Severity:    models.Low,
						Confidence:  models.MediumConfidence,
						URL:         target.URL,
						Evidence:    fmt.Sprintf("HSTS: %s", value),
						Description: "Strict-Transport-Security should include the includeSubDomains directive for full coverage.",
						Remediation: "Add 'includeSubDomains' to the Strict-Transport-Security header.",
						CWEID:       "CWE-523",
						ModuleID:    "headers",
					})
				}
			}

			if sc.Name == "Content-Security-Policy" {
				if strings.Contains(value, "unsafe-inline") || strings.Contains(value, "unsafe-eval") {
					findings = append(findings, &models.Finding{
						Title:       "CSP Allows unsafe-inline/unsafe-eval",
						Severity:    models.Medium,
						Confidence:  models.MediumConfidence,
						URL:         target.URL,
						Evidence:    fmt.Sprintf("CSP: %s", value),
						Description: "Content-Security-Policy allows unsafe-inline or unsafe-eval, reducing XSS protection.",
						Remediation: "Remove unsafe-inline and unsafe-eval from CSP. Use nonces or hashes for inline scripts.",
						CWEID:       "CWE-693",
						ModuleID:    "headers",
					})
				}
			}

			if sc.Name == "X-Frame-Options" {
				valLower := strings.ToLower(value)
				if valLower != "deny" && valLower != "sameorigin" {
					findings = append(findings, &models.Finding{
						Title:       "X-Frame-Options Allows Framing",
						Severity:    models.Medium,
						Confidence:  models.MediumConfidence,
						URL:         target.URL,
						Evidence:    fmt.Sprintf("X-Frame-Options: %s", value),
						Description: "X-Frame-Options should be set to DENY or SAMEORIGIN to prevent clickjacking.",
						Remediation: "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
						CWEID:       "CWE-1021",
						ModuleID:    "headers",
					})
				}
			}
		}
	}

	server := resp.Headers.Get("Server")
	if server != "" {
		findings = append(findings, &models.Finding{
			Title:       "Server Header Disclosure",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Server: %s", server),
			Description: "The Server header reveals web server software and version information.",
			Remediation: "Remove or obfuscate the Server header to reduce attack surface.",
			CWEID:       "CWE-200",
			ModuleID:    "headers",
		})
	}

	poweredBy := resp.Headers.Get("X-Powered-By")
	if poweredBy != "" {
		findings = append(findings, &models.Finding{
			Title:       "X-Powered-By Header Disclosure",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("X-Powered-By: %s", poweredBy),
			Description: "The X-Powered-By header reveals technology stack information.",
			Remediation: "Remove the X-Powered-By header to hide technology details.",
			CWEID:       "CWE-200",
			ModuleID:    "headers",
		})
	}

	xAspNetVersion := resp.Headers.Get("X-AspNet-Version")
	if xAspNetVersion != "" {
		findings = append(findings, &models.Finding{
			Title:       "ASP.NET Version Disclosure",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("X-AspNet-Version: %s", xAspNetVersion),
			Description: "ASP.NET version information is disclosed via X-AspNet-Version header.",
			Remediation: "Remove the X-AspNet-Version header in web.config.",
			CWEID:       "CWE-200",
			ModuleID:    "headers",
		})
	}

	for _, cookie := range resp.Cookies {
		var issues []string
		if !cookie.Secure {
			issues = append(issues, "Missing Secure flag")
		}
		if !cookie.HttpOnly {
			issues = append(issues, "Missing HttpOnly flag")
		}
		if cookie.SameSite != "Strict" && cookie.SameSite != "Lax" {
			issues = append(issues, "Missing SameSite attribute")
		}

		if len(issues) > 0 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Insecure Cookie: %s", cookie.Name),
				Severity:    models.Medium,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Evidence:    strings.Join(issues, ", "),
				Description: fmt.Sprintf("Cookie '%s' is missing security flags: %s", cookie.Name, strings.Join(issues, ", ")),
				Remediation: "Set Secure, HttpOnly, and SameSite flags on all cookies. Mark session cookies as HttpOnly.",
				CWEID:       "CWE-614",
				ModuleID:    "headers",
			})
		}

		host := strings.Split(target.URL, "://")[1]
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx > 0 {
			host = host[:idx]
		}
		if cookie.Domain != "" && cookie.Domain != host {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Cookie Domain Overreach: %s", cookie.Name),
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Cookie domain: %s, Target: %s", cookie.Domain, target.URL),
				Description: fmt.Sprintf("Cookie '%s' has a domain scope that may include subdomains beyond the current origin.", cookie.Name),
				Remediation: "Restrict cookie domain to the minimum necessary scope.",
				CWEID:       "CWE-200",
				ModuleID:    "headers",
			})
		}
	}

	return findings, nil
}

func init() {
	engine.GetRegistry().Register(&HeadersModule{})
}
