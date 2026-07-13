package adcs

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ADCSModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ADCSModule) ID() string   { return "adcs" }
func (m *ADCSModule) Name() string { return "Active Directory Certificate Services Scanner" }
func (m *ADCSModule) Description() string {
	return "Detects exposed AD CS endpoints, certificate enrollment services, ESC vulnerabilities, NTLM auth, and web enrollment"
}
func (m *ADCSModule) Severity() models.Severity { return models.Critical }

func (m *ADCSModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *ADCSModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")

	endpoints := []struct {
		path        string
		name        string
		description string
	}{
		{"/certsrv", "AD CS Web Enrollment", "Certificate Services web enrollment interface"},
		{"/CertSrv", "AD CS Web Enrollment (case-sensitive)", "Certificate Services web enrollment with alternate casing"},
		{"/CertEnroll", "AD CS Certificate Enrollment", "Certificate enrollment endpoint"},
		{"/certsrv/certfnsh.asp", "AD CS Certificate Finish", "Certificate request finalization page"},
		{"/certsrv/certrqst.asp", "AD CS Certificate Request", "Certificate request submission page"},
		{"/certsrv/certnew.cer", "AD CS Certificate Download", "Certificate download endpoint"},
		{"/CES", "Certificate Enrollment Service (CES)", "Certificate Enrollment Web Service"},
		{"/CEP", "Certificate Enrollment Policy (CEP)", "Certificate Enrollment Policy Web Service"},
		{"/ADPolicyProvider", "AD CS Policy Provider", "AD CS policy provider endpoint"},
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

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			bodyLower := strings.ToLower(resp.Body)
			adcsIndicators := []string{
				"microsoft", "certificate services", "certsrv", "certificate enrollment",
				"certificate authority", "active directory", "the certificate server",
				"certificate template", "web enrollment", "choose a certificate",
				"certificate request", "pkcs", "enter your information",
			}
			matched := false
			var matchedIndicator string
			for _, ind := range adcsIndicators {
				if strings.Contains(bodyLower, ind) {
					matched = true
					matchedIndicator = ind
					break
				}
			}

			if matched || resp.StatusCode == 401 || resp.StatusCode == 403 {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("AD CS - %s", ep.name),
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Endpoint %s returned HTTP %d (matched: '%s')", ep.path, resp.StatusCode, matchedIndicator),
					Description: fmt.Sprintf("%s is publicly accessible. AD CS exposure can lead to domain escalation (ESC attacks).", ep.description),
					Remediation: "Restrict AD CS endpoints to authorized users only. Use Extended Protection for Authentication. Consider disabling web enrollment if not needed.",
					CWEID:       "CWE-200",
					ModuleID:    "adcs",
				})
			}
		}
	}

	escPatterns := []struct {
		name    string
		pattern string
	}{
		{"ESC1 - Template SAN", "subject alternative name"},
		{"ESC1 - Template SAN", "san:"},
		{"ESC2 - Template Any Purpose", "any purpose"},
		{"ESC3 - Enrollment Agent", "enrollment agent"},
		{"ESC4 - ACL Overwrite", "access control"},
		{"ESC5 - PKI Object Access", "pki object"},
		{"ESC6 - CT_FLAG_AUTO_ENROLLMENT", "auto-enrollment"},
		{"ESC7 - CA Interface", "certificate authority interface"},
		{"ESC8 - NTLM Relay", "ntlm"},
		{"ESC9 - No Security Extension", "security extension"},
		{"ESC10 - Weak Certificate Mapping", "certificate mapping"},
		{"ESC11 - RPC Relay", "rpc"},
		{"ESC12 - Kerberos Relay", "kerberos"},
		{"ESC13 - CA ESC", "esc"},
		{"ESC14 - Template Based", "based on template"},
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
		for _, esc := range escPatterns {
			if strings.Contains(bodyLower, esc.pattern) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("AD CS - %s Pattern Detected", esc.name),
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Endpoint %s contains '%s' pattern in response body", ep.path, esc.pattern),
					Description: fmt.Sprintf("Potential %s vulnerability pattern detected in AD CS response. This could allow privilege escalation within the domain.", esc.name),
					Remediation: "Apply Microsoft security patches for AD CS. Review CA template permissions and configurations. Harden certificate enrollment policies.",
					CWEID:       "CWE-287",
					ModuleID:    "adcs",
				})
				break
			}
		}
	}

	ntlmPaths := []string{"/certsrv", "/CertEnroll", "/CES", "/CEP"}
	for _, np := range ntlmPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + np
		resp, err := m.client.DoRaw("GET", testURL, map[string]string{
			"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=",
		}, "")
		if err != nil {
			continue
		}

		authHeader := resp.Headers.Get("WWW-Authenticate")
		if strings.HasPrefix(strings.ToLower(authHeader), "ntlm") {
			findings = append(findings, &models.Finding{
				Title:       "AD CS - NTLM Authentication on Certificate Enrollment",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Endpoint %s responded with WWW-Authenticate: %s", np, authHeader),
				Description: "Certificate enrollment endpoint accepts NTLM authentication, which can be relayed (ESC8) or used for credential theft via NTLM relay attacks.",
				Remediation: "Disable NTLM authentication on AD CS endpoints. Use Kerberos or client certificate authentication instead. Enable Extended Protection for Authentication.",
				CWEID:       "CWE-287",
				ModuleID:    "adcs",
			})
		}
	}

	enrollmentPaths := []string{"/certsrv/certfnsh.asp", "/certsrv/certrqst.asp", "/certsrv/certnew.cer"}
	for _, ep := range enrollmentPaths {
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

		if resp.StatusCode == 200 {
			findings = append(findings, &models.Finding{
				Title:       "AD CS - Web Enrollment Exposed",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Certificate enrollment page %s is publicly accessible (HTTP 200)", ep),
				Description: "AD CS web enrollment interface is exposed. Attackers can request, approve, and download certificates, potentially leading to domain admin privileges.",
				Remediation: "Disable web enrollment if not required. If needed, restrict by IP and require smart card authentication. Use Extended Protection.",
				CWEID:       "CWE-287",
				ModuleID:    "adcs",
			})
		}
	}

	return findings, nil
}

func init() {
	engine.GetRegistry().Register(&ADCSModule{})
}
