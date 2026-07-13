package zday

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ZeroDayModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ZeroDayModule) ID() string   { return "0day" }
func (m *ZeroDayModule) Name() string { return "Zero-Day Emulation Module" }
func (m *ZeroDayModule) Description() string {
	return "Historical and modern zero-day vulnerability emulation and detection"
}
func (m *ZeroDayModule) Severity() models.Severity { return models.Critical }

type cveCheck struct {
	ID          string
	Description string
	Paths       []string
	Headers     map[string]string
	BodyCheck   []string
	StatusCode  int
	Method      string
	PostBody    string
	Severity    models.Severity
}

func (m *ZeroDayModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout), fanghttp.WithRateLimit(cfg.RateLimit))
	return nil
}

func (m *ZeroDayModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	checks := m.getCVEChecks()

	for _, cve := range checks {
		for _, path := range cve.Paths {
			fullURL := strings.TrimRight(target.URL, "/") + path

			var resp *fanghttp.Response
			var err error

			switch cve.Method {
			case "POST":
				req := fanghttp.NewRequest("POST", fullURL)
				req.Body = cve.PostBody
				if cve.Headers != nil {
					for k, v := range cve.Headers {
						req.Headers[k] = v
					}
				}
				resp, err = m.client.Do(req)
			default:
				headers := cve.Headers
				if headers == nil {
					headers = make(map[string]string)
				}
				baseURL := strings.TrimRight(target.URL, "/") + path
				u, parseErr := url.Parse(baseURL)
				if err == nil {
					_ = u
				}
				_ = parseErr
				resp, err = m.client.DoRaw("GET", baseURL, headers, "")
			}

			if err != nil {
				continue
			}

			if cve.StatusCode > 0 && resp.StatusCode != cve.StatusCode {
				continue
			}

			for _, check := range cve.BodyCheck {
				if strings.Contains(strings.ToLower(resp.Body), strings.ToLower(check)) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("Zero-Day: %s - %s", cve.ID, cve.Description),
						Severity:    cve.Severity,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Payload:     cve.PostBody,
						Evidence:    fmt.Sprintf("Response matched indicator: %s (status: %d)", check, resp.StatusCode),
						Description: fmt.Sprintf("Target appears vulnerable to %s (%s). Response contains identifiable signature.", cve.ID, cve.Description),
						Remediation: "Apply vendor security patch immediately. Check vendor advisory for mitigation steps.",
						CWEID:       cweForCVE(cve.ID),
						ModuleID:    "0day",
					})
					break
				}
			}
		}
	}

	return findings, nil
}

func (m *ZeroDayModule) getCVEChecks() []cveCheck {
	return []cveCheck{
		{
			ID: "CVE-2008-5416", Description: "IIS 6.0 WebDAV RCE",
			Paths:      []string{"/", "/webdav", "/scripts"},
			Headers:    map[string]string{"Destination": "http://localhost/evil.asp", "Content-Type": "application/xml"},
			BodyCheck:  []string{"WEBDAV", "Microsoft-IIS/6"},
			StatusCode: 207, Method: "PROPFIND", Severity: models.Critical,
		},
		{
			ID: "CVE-2012-1823", Description: "PHP CGI Argument Injection",
			Paths:      []string{"/index.php?-s", "/index.php?-d+allow_url_include=on"},
			BodyCheck:  []string{"<?php", "phpinfo"},
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2014-0160", Description: "Heartbleed OpenSSL Info Leak",
			Paths:     []string{"/"},
			Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			BodyCheck: []string{"heartbeat", "Heartbleed"},
			Method:    "POST", PostBody: "\x18\x03\x02\x00\x03\x01\x40\x00",
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2014-6271", Description: "Shellshock Bash RCE",
			Paths:      []string{"/cgi-bin/test", "/cgi-bin/test.cgi", "/cgi-sys/defaultwebpage.cgi"},
			Headers:    map[string]string{"User-Agent": "() { :;}; echo; echo FNG_SHELLSHOCK_TEST"},
			BodyCheck:  []string{"FNG_SHELLSHOCK_TEST"},
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2017-5638", Description: "Apache Struts2 RCE",
			Paths:      []string{"/", "/showcase", "/struts2-showcase"},
			Headers:    map[string]string{"Content-Type": "%{(#_='multipart/form-data')}"},
			BodyCheck:  []string{"Struts", "java.lang", "ognl"},
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2019-0708", Description: "BlueKeep RDP RCE",
			Paths:      []string{"/"},
			Headers:    map[string]string{"MS-RDP": "test"},
			BodyCheck:  []string{"MS-RDP", "RDP"},
			StatusCode: 0, Severity: models.Critical,
		},
		{
			ID: "CVE-2021-26855", Description: "ProxyLogon Exchange SSRF",
			Paths:      []string{"/ecp/", "/owa/", "/autodiscover/autodiscover.xml"},
			Headers:    map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Role": "mailbox"},
			BodyCheck:  []string{"Exchange", "OWA", "mailbox"},
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2022-22965", Description: "Spring4Shell RCE",
			Paths:      []string{"/", "/spring", "/api"},
			Headers:    map[string]string{"Suffix": "%>", "C1": "Runtime", "C2": "<%", "DNT": "1"},
			BodyCheck:  []string{"Spring", "org.springframework"},
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2023-4966", Description: "Citrix NetScaler ADC Info Leak",
			Paths:      []string{"/vpn/index.html", "/gw/info"},
			BodyCheck:  []string{"NetScaler", "Citrix", "ns_gw"},
			StatusCode: 200, Severity: models.Critical,
		},
		{
			ID: "CVE-2024-21887", Description: "Ivanti Connect Secure Command Injection",
			Paths:      []string{"/dana-na/auth/url/admin.cgi"},
			BodyCheck:  []string{"Ivanti", "Pulse", "admin"},
			StatusCode: 200, Severity: models.Critical,
		},
	}
}

func cweForCVE(cveID string) string {
	switch {
	case strings.Contains(cveID, "RCE"), strings.Contains(cveID, "rce"):
		return "CWE-94"
	case strings.Contains(cveID, "SSRF"), strings.Contains(cveID, "ssrf"):
		return "CWE-918"
	case strings.Contains(cveID, "Info"), strings.Contains(cveID, "Leak"):
		return "CWE-200"
	case strings.Contains(cveID, "Injection"):
		return "CWE-77"
	default:
		return "CWE-119"
	}
}

func init() {
	engine.GetRegistry().Register(&ZeroDayModule{})
}
