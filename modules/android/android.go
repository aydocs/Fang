package android

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type AndroidModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *AndroidModule) ID() string   { return "android" }
func (m *AndroidModule) Name() string { return "Android Security Assessment" }
func (m *AndroidModule) Description() string {
	return "Detects Android manifest exposure, APK downloads, Firebase misconfigurations, API key leaks, and debug endpoints"
}
func (m *AndroidModule) Severity() models.Severity { return models.Critical }

func (m *AndroidModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *AndroidModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkManifestExposure(ctx, target)...)
	findings = append(findings, m.checkAPKDownload(ctx, target)...)
	findings = append(findings, m.checkFirebaseMisconfig(ctx, target)...)
	findings = append(findings, m.checkDexSmaliFiles(ctx, target)...)
	findings = append(findings, m.checkGoogleAPIKey(ctx, target)...)
	findings = append(findings, m.checkDebugEndpoints(ctx, target)...)

	return findings, nil
}

var manifestPaths = []string{
	"/AndroidManifest.xml", "/manifest.xml",
	"/android/manifest.xml", "/android/AndroidManifest.xml",
	"/app/AndroidManifest.xml", "/application/AndroidManifest.xml",
}

func (m *AndroidModule) checkManifestExposure(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range manifestPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		body := resp.Body
		if strings.Contains(body, "<?xml") && strings.Contains(body, "manifest") &&
			(strings.Contains(body, "package=") || strings.Contains(body, "android:")) {
			permissions := extractPermissions(body)
			activities := extractActivities(body)

			evidence := fmt.Sprintf("AndroidManifest.xml exposed. Permissions: %d, Activities: %d", len(permissions), len(activities))
			if len(permissions) > 0 {
				evidence += fmt.Sprintf("\nPermissions: %s", strings.Join(permissions[:min(len(permissions), 10)], ", "))
			}

			findings = append(findings, &models.Finding{
				Title:       "Android Manifest File Exposed",
				Severity:    models.Critical,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    evidence,
				Description: fmt.Sprintf("AndroidManifest.xml is accessible at %s. This exposes app permissions, activities, services, and intent filters.", path),
				Remediation: "Remove AndroidManifest.xml from web-accessible directories. Use server rules to block access to XML files in app directories.",
				CWEID:       "CWE-200",
				ModuleID:    "android",
			})
		}
	}

	return findings
}

func extractPermissions(body string) []string {
	var permissions []string
	re := regexp.MustCompile(`android:name="([^"]*android\.permission\.[^"]*)"`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			permissions = append(permissions, m[1])
		}
	}
	return permissions
}

func extractActivities(body string) []string {
	var activities []string
	re := regexp.MustCompile(`android:name="([^"]*\.[^"]*)"`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			name := m[1]
			if !strings.Contains(name, "android.") && !strings.Contains(name, "permission") {
				activities = append(activities, name)
			}
		}
	}
	return activities
}

var apkPaths = []string{
	"/app.apk", "/application.apk",
	"/android.apk", "/release.apk",
	"/debug.apk", "/mobile.apk",
	"/download/app.apk", "/downloads/app.apk",
	"/apk/app.apk", "/static/app.apk",
}

func (m *AndroidModule) checkAPKDownload(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range apkPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		contentType := resp.Headers.Get("Content-Type")
		isAPK := strings.Contains(contentType, "application/vnd.android") ||
			strings.Contains(contentType, "application/octet-stream") ||
			strings.Contains(contentType, "application/java-archive")

		hasPKHeader := len(resp.Body) > 4 && resp.Body[:4] == "PK\u0003\u0004"

		if isAPK || hasPKHeader || strings.HasSuffix(path, ".apk") {
			findings = append(findings, &models.Finding{
				Title:       "APK Download Available",
				Severity:    models.High,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("APK file accessible at %s (Content-Type: %s)", path, contentType),
				Description: fmt.Sprintf("Android APK file is downloadable at %s. APK files can be decompiled to reveal source code, API keys, and security mechanisms.", path),
				Remediation: "Remove APK files from public web directories or restrict download access. Use code obfuscation if APK distribution is required.",
				CWEID:       "CWE-200",
				ModuleID:    "android",
			})
		}
	}

	return findings
}

func (m *AndroidModule) checkFirebaseMisconfig(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body

	firebaseRe := regexp.MustCompile(`(?:firebase\.io|firebaseio\.com|firebaseapp\.com|firebase\.google\.com)`)
	firebaseMatches := firebaseRe.FindAllString(body, -1)

	if len(firebaseMatches) > 0 {
		databaseURLRe := regexp.MustCompile(`https?://[^"'\s]*firebaseio\.com`)
		databaseURLs := databaseURLRe.FindAllString(body, -1)

		evidence := fmt.Sprintf("Firebase references found: %d matches", len(firebaseMatches))
		if len(databaseURLs) > 0 {
			evidence += fmt.Sprintf("\nDatabase URLs: %s", strings.Join(databaseURLs, ", "))
		}

		findings = append(findings, &models.Finding{
			Title:       "Firebase Configuration Exposure",
			Severity:    models.High,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    evidence,
			Description: "Firebase database URLs exposed in page content. Unsecured Firebase databases can be read/written by anyone.",
			Remediation: "Ensure Firebase Realtime Database and Firestore have proper security rules configured. Restrict database access to authenticated users only.",
			CWEID:       "CWE-200",
			ModuleID:    "android",
		})
	}

	return findings
}

var dexSmaliPaths = []string{
	"/classes.dex", "/classes2.dex", "/classes3.dex",
	"/app.dex", "/android.dex",
	"/smali", "/smali.zip", "/smali.tar.gz",
	"/app/smali", "/source/smali",
	"/dex", "/dex.zip",
}

func (m *AndroidModule) checkDexSmaliFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range dexSmaliPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyBytes := []byte(resp.Body)
		isDex := len(bodyBytes) > 8 && string(bodyBytes[:8]) == "dex\n035\u0000" ||
			len(bodyBytes) > 8 && string(bodyBytes[:8]) == "dex\n037\u0000" ||
			len(bodyBytes) > 8 && string(bodyBytes[:8]) == "dex\n038\u0000" ||
			len(bodyBytes) > 8 && string(bodyBytes[:8]) == "dex\n039\u0000"

		isZip := len(bodyBytes) > 4 && string(bodyBytes[:4]) == "PK\u0003\u0004"

		if isDex || isZip || strings.HasSuffix(path, ".dex") {
			fileType := "DEX"
			if strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar.gz") || isZip {
				fileType = "Smali/ZIP"
			}

			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Exposed %s File: %s", fileType, path),
				Severity:    models.Critical,
				Confidence:  models.CriticalConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("%s file accessible at %s (size: %d bytes)", fileType, path, len(resp.Body)),
				Description: fmt.Sprintf("%s file exposed at %s. DEX/Smali files can be decompiled to reveal app source code, business logic, and embedded secrets.", fileType, path),
				Remediation: "Remove DEX and Smali files from web-accessible directories. Use ProGuard/R8 obfuscation for Android apps.",
				CWEID:       "CWE-200",
				ModuleID:    "android",
			})
		}
	}

	return findings
}

func (m *AndroidModule) checkGoogleAPIKey(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body
	bodyLower := strings.ToLower(body)

	apiKeyRe := regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	apiKeyMatches := apiKeyRe.FindAllString(body, -1)

	if len(apiKeyMatches) > 0 {
		uniqueKeys := make(map[string]bool)
		for _, key := range apiKeyMatches {
			uniqueKeys[key] = true
		}

		var keyList []string
		for k := range uniqueKeys {
			keyList = append(keyList, k[:10]+"...")
		}

		findings = append(findings, &models.Finding{
			Title:       "Google API Key Exposed",
			Severity:    models.Critical,
			Confidence:  models.CriticalConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Found %d unique Google API key(s): %s", len(uniqueKeys), strings.Join(keyList, ", ")),
			Description: fmt.Sprintf("%d Google API key(s) exposed in page content. Unrestricted API keys can be abused for unauthorized access to Google services.", len(apiKeyMatches)),
			Remediation: "Remove API keys from client-side code. Use API key restrictions in Google Cloud Console. Rotate exposed keys immediately.",
			CWEID:       "CWE-522",
			ModuleID:    "android",
		})
	}

	if target.CrawlResult != nil {
		for _, scriptURL := range target.CrawlResult.Scripts {
			scriptResp, err := m.client.Get(scriptURL)
			if err != nil {
				continue
			}

			matches := apiKeyRe.FindAllString(scriptResp.Body, -1)
			if len(matches) > 0 {
				uniqueKeys := make(map[string]bool)
				for _, key := range matches {
					uniqueKeys[key] = true
				}

				var keyList []string
				for k := range uniqueKeys {
					keyList = append(keyList, k[:10]+"...")
				}

				findings = append(findings, &models.Finding{
					Title:       "Google API Key Exposed in JavaScript",
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         scriptURL,
					Evidence:    fmt.Sprintf("Found %d unique Google API key(s): %s", len(uniqueKeys), strings.Join(keyList, ", ")),
					Description: fmt.Sprintf("%d Google API key(s) exposed in JavaScript file. Keys in client-side code can be extracted by anyone.", len(matches)),
					Remediation: "Remove API keys from JavaScript. Use a backend proxy for API calls. Restrict API keys by referrer and IP in Google Cloud Console.",
					CWEID:       "CWE-522",
					ModuleID:    "android",
				})
			}
		}
	}

	_ = bodyLower
	return findings
}

var debugPaths = []string{
	"/dev", "/debug", "/test",
	"/dev/", "/debug/", "/test/",
	"/android/debug", "/app/debug",
	"/debug/log", "/dev/log",
	"/api/debug", "/api/dev", "/api/test",
	"/staging", "/beta",
	"/app/test", "/app/dev",
}

func (m *AndroidModule) checkDebugEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range debugPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		debugIndicators := []string{"debug", "dev", "test", "staging", "beta",
			"log", "trace", "verbose", "diagnostic",
			"console", "admin", "dashboard"}

		matched := 0
		for _, ind := range debugIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 2 {
			findings = append(findings, &models.Finding{
				Title:       "Android Debug Endpoint Exposed",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Debug/test endpoint accessible at %s (%d indicators matched)", path, matched),
				Description: fmt.Sprintf("Android debug or test endpoint exposed at %s. Debug endpoints may leak sensitive information or provide unauthorized access.", path),
				Remediation: "Remove debug endpoints from production builds. Disable Android logging (Log.x) in release builds using ProGuard.",
				CWEID:       "CWE-200",
				ModuleID:    "android",
			})
		}
	}

	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	engine.GetRegistry().Register(&AndroidModule{})
}
