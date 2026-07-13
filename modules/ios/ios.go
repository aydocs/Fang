package ios

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type IOSModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *IOSModule) ID() string   { return "ios" }
func (m *IOSModule) Name() string { return "iOS Security Assessment" }
func (m *IOSModule) Description() string {
	return "Detects IPA downloads, plist exposure, mobileprovision leaks, Apple API key leaks, URL scheme enumeration, and Crashlytics exposure"
}
func (m *IOSModule) Severity() models.Severity { return models.Critical }

func (m *IOSModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *IOSModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkIPADownload(ctx, target)...)
	findings = append(findings, m.checkPlistExposure(ctx, target)...)
	findings = append(findings, m.checkMobileProvision(ctx, target)...)
	findings = append(findings, m.checkAppleAPIKeys(ctx, target)...)
	findings = append(findings, m.checkURLSchemes(ctx, target)...)
	findings = append(findings, m.checkCrashlyticsEndpoints(ctx, target)...)

	return findings, nil
}

var ipaPaths = []string{
	"/app.ipa", "/application.ipa", "/ios.ipa",
	"/release.ipa", "/debug.ipa", "/mobile.ipa",
	"/download/app.ipa", "/downloads/app.ipa",
	"/ipa/app.ipa", "/static/app.ipa",
	"/build/app.ipa", "/ios/app.ipa",
}

func (m *IOSModule) checkIPADownload(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range ipaPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		contentType := resp.Headers.Get("Content-Type")
		isIPA := strings.Contains(contentType, "application/octet-stream") ||
			strings.Contains(contentType, "application/zip") ||
			strings.Contains(resp.URL, ".ipa")

		hasPKHeader := len(resp.Body) > 4 && resp.Body[:4] == "PK\u0003\u0004"

		if isIPA || hasPKHeader || strings.HasSuffix(path, ".ipa") {
			findings = append(findings, &models.Finding{
				Title:       "IPA Download Available",
				Severity:    models.High,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("IPA file accessible at %s (Content-Type: %s, size: %d bytes)", path, contentType, len(resp.Body)),
				Description: fmt.Sprintf("iOS IPA file is downloadable at %s. IPA files can be decompiled to reveal source code, API keys, and security mechanisms.", path),
				Remediation: "Remove IPA files from public web directories or restrict download access. Use code obfuscation if IPA distribution is required.",
				CWEID:       "CWE-200",
				ModuleID:    "ios",
			})
		}
	}

	return findings
}

var plistPaths = []string{
	"/app.plist", "/manifest.plist", "/info.plist",
	"/ios.plist", "/application.plist",
	"/download.plist", "/install.plist",
	"/itunes.plist", "/itmsp.plist",
	"/plist/app.plist", "/static/app.plist",
}

func (m *IOSModule) checkPlistExposure(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range plistPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		body := resp.Body
		bodyLower := strings.ToLower(body)
		isPlist := strings.Contains(body, "<?xml") &&
			(strings.Contains(bodyLower, "<plist") || strings.Contains(bodyLower, "!doctype plist"))

		if isPlist || strings.Contains(bodyLower, "itunes") || strings.Contains(bodyLower, "bundle-identifier") {
			hasBundleID := strings.Contains(bodyLower, "bundle-identifier") || strings.Contains(bodyLower, "cfbundleidentifier")
			hasVersion := strings.Contains(bodyLower, "cfbundleversion") || strings.Contains(bodyLower, "cfbundleshortversionstring")
			hasURLScheme := strings.Contains(bodyLower, "cfbundleurltypes") || strings.Contains(bodyLower, "urlschemes")

			evidence := fmt.Sprintf("Plist file exposed at %s", path)
			var details []string
			if hasBundleID {
				details = append(details, "bundle identifier found")
			}
			if hasVersion {
				details = append(details, "version info found")
			}
			if hasURLScheme {
				details = append(details, "URL schemes found")
			}
			if len(details) > 0 {
				evidence += " (" + strings.Join(details, ", ") + ")"
			}

			findings = append(findings, &models.Finding{
				Title:       "iOS Plist File Exposed",
				Severity:    models.High,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    evidence,
				Description: fmt.Sprintf("iOS property list (plist) file exposed at %s. Plist files contain app configuration, bundle identifiers, and may contain sensitive keys.", path),
				Remediation: "Remove plist files from web-accessible directories. Ensure plist files are not included in web server document roots.",
				CWEID:       "CWE-200",
				ModuleID:    "ios",
			})
		}
	}

	return findings
}

var mobileProvisionPaths = []string{
	"/embedded.mobileprovision", "/mobileprovision",
	"/app.mobileprovision", "/ios.mobileprovision",
	"/provision.mobileprovision", "/profile.mobileprovision",
	"/distribution.mobileprovision", "/development.mobileprovision",
}

func (m *IOSModule) checkMobileProvision(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range mobileProvisionPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		body := resp.Body
		bodyLower := strings.ToLower(body)

		isProvision := strings.Contains(body, "<?xml") &&
			(strings.Contains(bodyLower, "provision") ||
				strings.Contains(bodyLower, "team-identifier") ||
				strings.Contains(bodyLower, "appidname") ||
				strings.Contains(bodyLower, "provisioneddevices"))

		if isProvision || strings.Contains(bodyLower, "mobileprovision") {
			findings = append(findings, &models.Finding{
				Title:       "iOS Mobile Provisioning File Exposed",
				Severity:    models.Critical,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Mobile provision file accessible at %s", path),
				Description: fmt.Sprintf("iOS mobile provisioning profile exposed at %s. This file contains team identifiers, app IDs, and may include device UDIDs and certificates.", path),
				Remediation: "Remove mobileprovision files from public web directories. Provisioning profiles should not be distributed publicly.",
				CWEID:       "CWE-200",
				ModuleID:    "ios",
			})
		}
	}

	return findings
}

var appleKeyPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Apple Push Notification Key", regexp.MustCompile(`(?i)[a-z0-9]{10,20}\.p8`)},
	{"Apple Team ID", regexp.MustCompile(`(?i)[A-Z0-9]{10}`)},
	{"Apple Music Key", regexp.MustCompile(`(?i)apple[m]?usic.*key[:\s]+[a-z0-9\-_]{10,}`)},
	{"iCloud Token", regexp.MustCompile(`(?i)icloud.*(?:token|key|secret)[:\s]+[a-z0-9\-_]{8,}`)},
	{"APNs Key ID", regexp.MustCompile(`(?i)apns.*key[:\s]+[a-z0-9\-_]{10,}`)},
	{"Apple ID Credential", regexp.MustCompile(`(?i)apple.*(?:id|account).*password[:\s]+[^\s]{6,}`)},
	{"Sign in with Apple", regexp.MustCompile(`(?i)apple.*client[:\s]*[a-z0-9\-_]+\.[a-z0-9\-_]+`)},
}

func (m *IOSModule) checkAppleAPIKeys(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body

	for _, ap := range appleKeyPatterns {
		matches := ap.Pattern.FindAllString(body, -1)
		if len(matches) > 0 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Apple %s Exposed", ap.Name),
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Found %d match(es) for %s pattern", len(matches), ap.Name),
				Description: fmt.Sprintf("Apple %s exposed in page content. This could allow unauthorized access to Apple services.", ap.Name),
				Remediation: "Remove Apple API keys and secrets from client-side code. Store credentials in secure server-side configuration or use environment variables.",
				CWEID:       "CWE-200",
				ModuleID:    "ios",
			})
		}
	}

	if target.CrawlResult != nil {
		for _, scriptURL := range target.CrawlResult.Scripts {
			scriptResp, err := m.client.Get(scriptURL)
			if err != nil {
				continue
			}

			for _, ap := range appleKeyPatterns {
				matches := ap.Pattern.FindAllString(scriptResp.Body, -1)
				if len(matches) > 0 {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("Apple %s Exposed in JavaScript", ap.Name),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         scriptURL,
						Evidence:    fmt.Sprintf("Found %d match(es) for %s pattern in JS", len(matches), ap.Name),
						Description: fmt.Sprintf("Apple %s exposed in JavaScript file. Credentials in client-side code can be extracted by anyone.", ap.Name),
						Remediation: "Remove Apple secrets from JavaScript files. Use a secure backend proxy for API calls requiring Apple credentials.",
						CWEID:       "CWE-200",
						ModuleID:    "ios",
					})
				}
			}
		}
	}

	return findings
}

func (m *IOSModule) checkURLSchemes(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body

	schemeRe := regexp.MustCompile(`(?i)([a-zA-Z][a-zA-Z0-9+\-.]*)://`)
	schemeMatches := schemeRe.FindAllStringSubmatch(body, -1)

	schemeCounts := make(map[string]int)
	for _, m := range schemeMatches {
		if len(m) > 1 {
			scheme := strings.ToLower(m[1])
			if scheme != "http" && scheme != "https" && scheme != "ftp" &&
				scheme != "ws" && scheme != "wss" && scheme != "mailto" &&
				scheme != "tel" && scheme != "sms" && scheme != "file" &&
				scheme != "data" && scheme != "javascript" {
				schemeCounts[scheme]++
			}
		}
	}

	if len(schemeCounts) > 0 {
		var schemeList []string
		for s, c := range schemeCounts {
			schemeList = append(schemeList, fmt.Sprintf("%s (%d)", s, c))
		}

		findings = append(findings, &models.Finding{
			Title:       "iOS Custom URL Schemes Enumerated",
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Custom URL schemes found: %s", strings.Join(schemeList, ", ")),
			Description: fmt.Sprintf("%d custom URL scheme(s) detected in page content. Custom URL schemes can be used for deep linking and may expose attack surface for iOS app interception.", len(schemeCounts)),
			Remediation: "Validate all incoming URL scheme requests in iOS apps. Use universal links instead of custom URL schemes where possible.",
			CWEID:       "CWE-200",
			ModuleID:    "ios",
		})
	}

	return findings
}

var crashlyticsPaths = []string{
	"/crashlytics", "/fabric", "/api/crashlytics",
	"/crash", "/crash-report", "/api/crash",
	"/firebase/crashlytics", "/fabric/crashlytics",
	"/crashlytics/api", "/api/fabric",
}

func (m *IOSModule) checkCrashlyticsEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range crashlyticsPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		crashIndicators := []string{"crashlytics", "fabric", "crash", "exception",
			"stacktrace", "stack trace", "error report",
			"firebase", "analytics", "session"}

		matched := 0
		for _, ind := range crashIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 2 {
			findings = append(findings, &models.Finding{
				Title:       "Crashlytics/Fabric Endpoint Exposed",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Crashlytics-related endpoint accessible at %s (%d indicators matched)", path, matched),
				Description: fmt.Sprintf("Crashlytics or Fabric endpoint exposed at %s. These endpoints may leak crash reports, error details, and application stack traces.", path),
				Remediation: "Restrict access to crash reporting endpoints. Ensure crash reports do not contain sensitive user data. Configure proper API authentication.",
				CWEID:       "CWE-200",
				ModuleID:    "ios",
			})
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&IOSModule{})
}
