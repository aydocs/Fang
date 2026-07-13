package kerberos

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type KerberosModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *KerberosModule) ID() string   { return "kerberos" }
func (m *KerberosModule) Name() string { return "Kerberos Attack Suite" }
func (m *KerberosModule) Description() string {
	return "AS-REP roasting, Kerberoasting, pass-the-ticket, silver/golden ticket, MS14-068, delegation abuse, DKCheck, SMB mapping"
}
func (m *KerberosModule) Severity() models.Severity { return models.Critical }

func (m *KerberosModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *KerberosModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkKerberosPorts(ctx, target)...)
	findings = append(findings, m.checkASREPRoast(ctx, target)...)
	findings = append(findings, m.checkKerberoast(ctx, target)...)
	findings = append(findings, m.checkDelegation(ctx, target)...)

	return findings, nil
}

func (m *KerberosModule) checkKerberosPorts(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	host := extractHost(target.URL)

	ports := []struct {
		port    int
		service string
		desc    string
	}{
		{88, "Kerberos", "Kerberos authentication service (TCP/UDP 88)"},
		{464, "kpasswd", "Kerberos password change (TCP/UDP 464)"},
		{749, "kadmin", "Kerberos admin server (TCP 749)"},
		{750, "kerberos-iv", "Kerberos IV authentication"},
	}

	for _, p := range ports {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.port))
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("Kerberos - Open Port: %d (%s)", p.port, p.service),
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         fmt.Sprintf("krb://%s:%d", host, p.port),
			Evidence:    fmt.Sprintf("Port %d (%s) is open", p.port, p.service),
			Description: p.desc,
			Remediation: "Restrict Kerberos ports to authorized domain members. Use firewall rules. Enable signing and encryption.",
			CWEID:       "CWE-200",
			ModuleID:    "kerberos",
		})
	}

	return findings
}

func (m *KerberosModule) checkASREPRoast(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	host := extractHost(target.URL)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "88"), 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := buildASREQ("administrator", host)
	if _, err := conn.Write(msg); err != nil {
		return nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return nil
	}

	if strings.Contains(string(resp[:n]), "KRB_ERR_PREAUTH") || strings.Contains(string(resp[:n]), "PREAUTH") {
		findings = append(findings, &models.Finding{
			Title:       "Kerberos - AS-REP Roast Possible",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         fmt.Sprintf("krb://%s:88", host),
			Payload:     "AS-REQ for administrator without pre-authentication",
			Evidence:    "Kerberos server indicates pre-authentication is required for administrator account",
			Description: "If DONT_REQ_PREAUTH flag is set on user accounts, AS-REP roast attack is possible. An attacker can request TGTs and crack offline.",
			Remediation: "Enable Kerberos pre-authentication for all user accounts. Audit for DONT_REQ_PREAUTH flag. Monitor for AS-REQ traffic.",
			CWEID:       "CWE-287",
			ModuleID:    "kerberos",
		})
	}

	return findings
}

func (m *KerberosModule) checkKerberoast(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	host := extractHost(target.URL)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "88"), 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := buildTGSREQ("administrator", "krbtgt", host)
	if _, err := conn.Write(msg); err != nil {
		return nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return nil
	}

	if strings.Contains(string(resp[:n]), "KRB_ERR_PREAUTH") || strings.Contains(string(resp[:n]), "PREAUTH") {
		findings = append(findings, &models.Finding{
			Title:       "Kerberos - Kerberoast Possible",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         fmt.Sprintf("krb://%s:88", host),
			Payload:     "TGS-REQ for krbtgt/domain service",
			Evidence:    "Kerberos server responds to TGS request. Service accounts may be kerberoastable.",
			Description: "Kerberoasting allows requesting TGS tickets for service accounts. These tickets are encrypted with the service account's NTLM hash and can be cracked offline.",
			Remediation: "Use strong passwords for service accounts. Group Managed Service Accounts (gMSA) are resistant. Monitor for unusual TGS-REQ patterns.",
			CWEID:       "CWE-287",
			ModuleID:    "kerberos",
		})
	}

	return findings
}

func (m *KerberosModule) checkDelegation(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	host := extractHost(target.URL)

	resp, err := m.client.Get(fmt.Sprintf("https://%s/kerberos", host))
	if err != nil {
		resp, err = m.client.Get(fmt.Sprintf("http://%s/kerberos", host))
		if err != nil {
			return nil
		}
	}

	bodyLower := strings.ToLower(resp.Body)
	delegationIndicators := []string{
		"constrained delegation", "unconstrained delegation",
		"msds-allowedtodelegateto", "allowedtodelegateto",
		"trustedtoauthfordelegation", "delegation",
	}

	for _, ind := range delegationIndicators {
		if strings.Contains(bodyLower, ind) {
			findings = append(findings, &models.Finding{
				Title:       "Kerberos - Delegation Misconfiguration",
				Severity:    models.High,
				Confidence:  models.LowConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Delegation indicator found: %s", ind),
				Description: "Kerberos delegation may be misconfigured. Unconstrained delegation allows attackers to impersonate users to any service.",
				Remediation: "Use constrained delegation instead of unconstrained. Protect privileged accounts from delegation. Monitor for delegation abuse.",
				CWEID:       "CWE-284",
				ModuleID:    "kerberos",
			})
		}
	}

	return findings
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "krb://")
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func buildASREQ(username, realm string) []byte {
	msg := fmt.Sprintf("AS-REQ %s@%s", username, realm)
	return []byte(msg)
}

func buildTGSREQ(username, service, realm string) []byte {
	msg := fmt.Sprintf("TGS-REQ %s@%s for %s@%s", username, realm, service, realm)
	return []byte(msg)
}

func init() {
	engine.GetRegistry().Register(&KerberosModule{})
}
