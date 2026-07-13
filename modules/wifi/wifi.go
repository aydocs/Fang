package wifi

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type WifiModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *WifiModule) ID() string   { return "wifi" }
func (m *WifiModule) Name() string { return "WiFi Security Assessment" }
func (m *WifiModule) Description() string {
	return "Detects exposed WiFi credentials, WiFi config file leaks, captive portal bypass, and WPS vulnerabilities"
}
func (m *WifiModule) Severity() models.Severity { return models.Critical }

func (m *WifiModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *WifiModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkWifiEndpoints(ctx, target)...)
	findings = append(findings, m.checkExposedCredentials(ctx, target)...)
	findings = append(findings, m.checkConfigLeaks(ctx, target)...)
	findings = append(findings, m.checkCaptivePortalBypass(ctx, target)...)
	findings = append(findings, m.checkWPSEnabled(ctx, target)...)

	return findings, nil
}

var wifiEndpoints = []string{
	"/wifi", "/api/wifi", "/wifi/config", "/wifi/status",
	"/wireless", "/api/wireless", "/wlan", "/api/wlan",
	"/network/wifi", "/router/wifi", "/config/wifi",
	"/api/v1/wifi", "/api/v2/wifi", "/system/wifi",
	"/wifi/settings", "/wifi/scan", "/wifi/networks",
	"/api/network/wifi", "/rest/wifi",
}

func (m *WifiModule) checkWifiEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range wifiEndpoints {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		wifiIndicators := []string{"ssid", "network", "signal", "channel", "bssid",
			"frequency", "encryption", "wpa", "wep", "rssi",
			"wireless", "access point", "ap"}

		matched := 0
		for _, ind := range wifiIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 2 {
			findings = append(findings, &models.Finding{
				Title:       "WiFi Network Scanning Endpoint Exposed",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("WiFi endpoint accessible with %d network indicators matched", matched),
				Description: fmt.Sprintf("WiFi management endpoint %s is exposed. This may allow network scanning and configuration discovery.", path),
				Remediation: "Restrict access to WiFi management endpoints. Implement authentication and network-level access controls.",
				CWEID:       "CWE-200",
				ModuleID:    "wifi",
			})
		}
	}

	return findings
}

func (m *WifiModule) checkExposedCredentials(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	bodyLower := strings.ToLower(resp.Body)

	ssidRe := strings.Count(bodyLower, "ssid")
	passwordRe := strings.Count(bodyLower, "password")
	pskRe := strings.Count(bodyLower, "psk")
	wpaKeyRe := strings.Count(bodyLower, "wpa_key")
	passphraseRe := strings.Count(bodyLower, "passphrase")
	wirelessKeyRe := strings.Count(bodyLower, "wireless_key")

	totalMatches := ssidRe + passwordRe + pskRe + wpaKeyRe + passphraseRe + wirelessKeyRe

	if totalMatches >= 3 {
		ssidExtract := ""
		idx := strings.Index(bodyLower, "ssid")
		if idx >= 0 {
			start := idx - 20
			if start < 0 {
				start = 0
			}
			end := idx + 60
			if end > len(bodyLower) {
				end = len(bodyLower)
			}
			ssidExtract = bodyLower[start:end]
		}

		findings = append(findings, &models.Finding{
			Title:       "Exposed WiFi Credentials in Page Content",
			Severity:    models.Critical,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("WiFi credential patterns found (SSID:%d, password:%d, PSK:%d). Context: %s", ssidRe, passwordRe, pskRe, ssidExtract),
			Description: "WiFi credentials (SSID and passwords) exposed in page content. This could allow unauthorized network access.",
			Remediation: "Remove WiFi credentials from publicly accessible pages. Store credentials securely and use proper access controls.",
			CWEID:       "CWE-522",
			ModuleID:    "wifi",
		})
	}

	if target.CrawlResult != nil {
		for _, scriptURL := range target.CrawlResult.Scripts {
			scriptResp, err := m.client.Get(scriptURL)
			if err != nil {
				continue
			}

			scriptBody := strings.ToLower(scriptResp.Body)
			if (strings.Contains(scriptBody, "ssid") && strings.Contains(scriptBody, "password")) ||
				(strings.Contains(scriptBody, "ssid") && strings.Contains(scriptBody, "psk")) {
				findings = append(findings, &models.Finding{
					Title:       "WiFi Credentials in JavaScript File",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         scriptURL,
					Evidence:    "SSID and password/PSK found together in JavaScript file",
					Description: "WiFi credentials embedded in JavaScript files. These are accessible to any visitor and can be extracted.",
					Remediation: "Remove WiFi credentials from client-side JavaScript. Use server-side configuration instead.",
					CWEID:       "CWE-522",
					ModuleID:    "wifi",
				})
			}
		}
	}

	return findings
}

var wifiConfigPaths = []string{
	"/wpa_supplicant.conf", "/wpa_supplicant.conf.bak",
	"/NetworkManager/system-connections/",
	"/etc/NetworkManager/system-connections/",
	"/wireless.config", "/wireless.cfg",
	"/wifi.conf", "/wifi.cfg",
	"/hostapd.conf", "/hostapd.config",
	"/etc/wpa_supplicant/wpa_supplicant.conf",
	"/config/wireless", "/config/wifi.conf",
	"/router/config/wireless",
	"/backup/wifi.conf", "/backup/wpa_supplicant.conf",
}

func (m *WifiModule) checkConfigLeaks(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range wifiConfigPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		isConfig := strings.Contains(bodyLower, "ssid") ||
			strings.Contains(bodyLower, "psk") ||
			strings.Contains(bodyLower, "wpa") ||
			strings.Contains(bodyLower, "network=") ||
			strings.Contains(bodyLower, "key_mgmt") ||
			strings.Contains(bodyLower, "wpa_passphrase") ||
			strings.Contains(bodyLower, "wireless")

		if isConfig {
			configType := "WiFi configuration"
			if strings.Contains(path, "wpa_supplicant") {
				configType = "wpa_supplicant configuration"
			} else if strings.Contains(path, "NetworkManager") {
				configType = "NetworkManager configuration"
			} else if strings.Contains(path, "hostapd") {
				configType = "hostapd access point configuration"
			}

			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("WiFi Configuration File Leaked: %s", path),
				Severity:    models.Critical,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Accessible %s file found containing network configuration", configType),
				Description: fmt.Sprintf("%s file is exposed at %s. This file typically contains network credentials and security settings.", configType, path),
				Remediation: "Remove leaked configuration files. Ensure config files are not in the web root. Use proper file permissions.",
				CWEID:       "CWE-522",
				ModuleID:    "wifi",
			})
		}
	}

	return findings
}

var captivePortalPaths = []string{
	"/captive", "/captive-portal", "/portal",
	"/api/captive", "/captiveportal",
	"/gw", "/hotspot", "/auth",
	"/login", "/portal-login",
	"/status", "/api/portal",
}

func (m *WifiModule) checkCaptivePortalBypass(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range captivePortalPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		portalIndicators := []string{"captive", "portal", "hotspot", "authenticate",
			"accept", "terms", "agree", "login", "wifi"}

		matched := 0
		for _, ind := range portalIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 3 {
			bypassMethods := []string{
				"/generate_204", "/gen_204", "/ncsi.txt",
				"/connecttest.txt", "/hotspot-detect.html",
				"/library/test/success.html",
			}

			var accessibleBypass []string
			for _, bp := range bypassMethods {
				bpURL := strings.TrimRight(target.URL, "/") + bp
				bpResp, err := m.client.Get(bpURL)
				if err == nil && bpResp.StatusCode == 200 {
					accessibleBypass = append(accessibleBypass, bp)
				}
			}

			evidence := fmt.Sprintf("Captive portal at %s with %d bypass endpoints accessible", path, len(accessibleBypass))
			if len(accessibleBypass) > 0 {
				evidence += fmt.Sprintf(": %s", strings.Join(accessibleBypass, ", "))
			}

			findings = append(findings, &models.Finding{
				Title:       "Captive Portal Bypass Possible",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    evidence,
				Description: fmt.Sprintf("Captive portal endpoint found at %s with %d potential bypass methods available.", path, len(accessibleBypass)),
				Remediation: "Secure captive portal by implementing proper authentication for all endpoints. Block known bypass URLs.",
				CWEID:       "CWE-200",
				ModuleID:    "wifi",
			})
		}
	}

	return findings
}

var wpsPaths = []string{
	"/wps", "/api/wps", "/wps/config",
	"/router/wps", "/config/wps",
	"/wps/pin", "/wps/status",
	"/api/v1/wps", "/api/router/wps",
}

func (m *WifiModule) checkWPSEnabled(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range wpsPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		wpsIndicators := []string{"wps", "pin", "push button", "pbc",
			"enabled", "configured", "active", "status",
			"wps_pin", "wps_config"}

		matched := 0
		for _, ind := range wpsIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 2 {
			enabled := strings.Contains(bodyLower, "enabled") ||
				strings.Contains(bodyLower, "true") ||
				strings.Contains(bodyLower, "active") ||
				strings.Contains(bodyLower, "1")

			severity := models.Medium
			confidence := models.MediumConfidence
			if enabled {
				severity = models.High
				confidence = models.HighConfidence
			}

			findings = append(findings, &models.Finding{
				Title:       "WPS Endpoint Detected on Router Admin Panel",
				Severity:    severity,
				Confidence:  confidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("WPS endpoint accessible at %s (enabled: %v)", path, enabled),
				Description: fmt.Sprintf("WiFi Protected Setup (WPS) endpoint found at %s. WPS is vulnerable to PIN brute-force attacks allowing unauthorized network access.", path),
				Remediation: "Disable WPS on the router. WPS PIN authentication is vulnerable to brute-force attacks (the 8-digit PIN can be cracked in hours).",
				CWEID:       "CWE-200",
				ModuleID:    "wifi",
			})
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&WifiModule{})
}
