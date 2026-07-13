package exchange

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ExchangeModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ExchangeModule) ID() string   { return "exchange" }
func (m *ExchangeModule) Name() string { return "Microsoft Exchange Scanner" }
func (m *ExchangeModule) Description() string {
	return "Detects exposed Exchange endpoints including OWA, ECP, EWS, Autodiscover, ProxyLogon, and information leaks"
}
func (m *ExchangeModule) Severity() models.Severity { return models.Critical }

func (m *ExchangeModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *ExchangeModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")

	endpoints := []struct {
		path        string
		name        string
		description string
	}{
		{"/owa", "Outlook Web App (OWA)", "OWA login interface"},
		{"/ecp", "Exchange Control Panel (ECP)", "Exchange admin control panel"},
		{"/ews", "Exchange Web Services (EWS)", "Exchange Web Services SOAP endpoint"},
		{"/autodiscover", "Autodiscover Service", "Exchange Autodiscover configuration service"},
		{"/rpc", "RPC over HTTP", "Outlook Anywhere RPC endpoint"},
		{"/mapi", "MAPI over HTTP", "MAPI HTTP endpoint for Outlook connectivity"},
		{"/powershell", "Exchange PowerShell", "Exchange Remote PowerShell endpoint"},
		{"/Microsoft-Server-ActiveSync", "ActiveSync", "Exchange ActiveSync endpoint"},
		{"/oab", "Offline Address Book", "Exchange Offline Address Book"},
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + ep.path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		exchangeIndicators := []string{
			"outlook", "exchange", "owa", "microsoft", "ecp",
			"autodiscover", "activesync", "mailbox",
			"the page you are trying to access", "exchange control panel",
			"outlook web app", "outlook anywhere",
		}
		matched := false
		var matchedIndicator string
		for _, ind := range exchangeIndicators {
			if strings.Contains(bodyLower, ind) {
				matched = true
				matchedIndicator = ind
				break
			}
		}

		if matched || (resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 401 || resp.StatusCode == 403) {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Exchange - %s", ep.name),
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Endpoint %s returned HTTP %d (matched: '%s')", ep.path, resp.StatusCode, matchedIndicator),
				Description: fmt.Sprintf("%s is accessible. Exchange attack surface includes known CVEs (ProxyLogon, ProxyShell, etc.).", ep.description),
				Remediation: "Apply latest Exchange Cumulative Updates. Restrict Exchange endpoints with VPN or reverse proxy. Enable MFA on all mailboxes.",
				CWEID:       "CWE-200",
				ModuleID:    "exchange",
			})
		}
	}

	owaLoginURL := baseURL + "/owa/auth/logon.aspx"
	resp, err := m.client.Get(owaLoginURL)
	if err == nil {
		bodyLower := strings.ToLower(resp.Body)
		if resp.StatusCode == 200 && (strings.Contains(bodyLower, "logon") || strings.Contains(bodyLower, "password") || strings.Contains(bodyLower, "sign in") || strings.Contains(bodyLower, "outlook")) {
			findings = append(findings, &models.Finding{
				Title:       "Exchange - OWA Login Page Accessible",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         owaLoginURL,
				Evidence:    fmt.Sprintf("OWA login page accessible at /owa/auth/logon.aspx (HTTP %d)", resp.StatusCode),
				Description: "Outlook Web App login page is publicly accessible. This is a primary target for password spraying and credential attacks.",
				Remediation: "Place OWA behind a VPN or reverse proxy. Enable MFA and account lockout policies. Monitor for brute force attempts.",
				CWEID:       "CWE-287",
				ModuleID:    "exchange",
			})
		}
	}

	autodiscoverURL := baseURL + "/autodiscover/autodiscover.xml"
	autodiscoverBody := `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
<Request>
<EMailAddress>user@target.com</EMailAddress>
<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
</Request>
</Autodiscover>`

	resp, err = m.client.DoRaw("POST", autodiscoverURL, map[string]string{"Content-Type": "text/xml"}, autodiscoverBody)
	if err == nil {
		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(resp.Body)
			leakIndicators := []string{
				"displayname", "emailaddress", "mailbox", "servername",
				"server", "dnsserver", "domain", "legacydn",
				"protocol", "asurl", "ewsurl", "oaburl",
				"externalserver", "internalserver", "internalurl",
			}
			var evidence []string
			for _, ind := range leakIndicators {
				if strings.Contains(bodyLower, ind) {
					evidence = append(evidence, ind)
				}
			}
			if len(evidence) > 0 {
				findings = append(findings, &models.Finding{
					Title:       "Exchange - Autodiscover Information Leak",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         autodiscoverURL,
					Evidence:    fmt.Sprintf("Autodiscover returned internal configuration data: %s", strings.Join(evidence, ", ")),
					Description: "Exchange Autodiscover service leaks internal server names, URLs, and domain information that aids further attacks.",
					Remediation: "Restrict Autodiscover access to authenticated clients. Consider using a reverse proxy to filter sensitive fields in responses.",
					CWEID:       "CWE-200",
					ModuleID:    "exchange",
				})
			}
		}

		if strings.Contains(resp.Body, "Error: 401") || strings.Contains(strings.ToLower(resp.Body), "unauthorized") {
		}
	}

	proxylogonPaths := []string{
		"/ecp/DDI/DDIService.svc/GetList?schema=Mailbox&msExchEcpCanary=SOMECANARY",
		"/ecp/DDI/DDIService.svc/GetObject?schema=Mailbox&msExchEcpCanary=SOMECANARY",
		"/ecp/DDI/DDIService.svc/SetObject?schema=Mailbox&msExchEcpCanary=SOMECANARY",
		"/owa/auth/x.js",
		"/ecp/auth/x.js",
	}

	ssrfHeaders := map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Remote-IP":       "127.0.0.1",
		"X-Originating-IP":  "[127.0.0.1]",
		"X-Remote-Endpoint": "127.0.0.1",
		"Client-IP":         "127.0.0.1",
	}

	for _, pp := range proxylogonPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + pp
		resp, err := m.client.DoRaw("GET", testURL, ssrfHeaders, "")
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 500 {
			bodyLower := strings.ToLower(resp.Body)
			plIndicators := []string{
				"mailbox", "distinguishedname", "legacydn", "servername",
				"externalemailaddress", "msexchecpcanary", "emailaddresses",
				"displayname", "windowsemailaddress",
			}
			matchedCount := 0
			for _, ind := range plIndicators {
				if strings.Contains(bodyLower, ind) {
					matchedCount++
				}
			}

			if matchedCount >= 2 {
				findings = append(findings, &models.Finding{
					Title:       "Exchange - ProxyLogon Pattern (CVE-2021-26855)",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Endpoint %s returned data via SSRF bypass with %d Exchange indicators", pp, matchedCount),
					Description: "Exchange server appears vulnerable to ProxyLogon (CVE-2021-26855). SSRF via backend header bypass allows pre-auth access to Exchange endpoints.",
					Remediation: "Apply Microsoft Exchange security update from March 2021 (or later CU). Restrict Exchange endpoints with VPN or reverse proxy.",
					CWEID:       "CWE-287",
					ModuleID:    "exchange",
				})
				goto ecpCheck
			}
		}
	}

ecpCheck:
	ecpPaths := []string{"/ecp", "/ecp/default.aspx", "/ecp/logon.aspx", "/ecp/About.aspx"}
	for _, ep := range ecpPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + ep
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		if resp.StatusCode == 200 && (strings.Contains(bodyLower, "exchange control panel") || strings.Contains(bodyLower, "ecp") || strings.Contains(bodyLower, "admin")) {
			findings = append(findings, &models.Finding{
				Title:       "Exchange - ECP Admin Panel Accessible",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Exchange Control Panel at %s returned HTTP 200", ep),
				Description: "Exchange Control Panel (ECP) is publicly accessible. This grants administrative access to Exchange configuration and all mailboxes.",
				Remediation: "Restrict /ecp to internal admin workstations only. Use VPN access. Apply MFA for all admin accounts.",
				CWEID:       "CWE-287",
				ModuleID:    "exchange",
			})
			break
		}
	}

	return findings, nil
}

func init() {
	engine.GetRegistry().Register(&ExchangeModule{})
}
