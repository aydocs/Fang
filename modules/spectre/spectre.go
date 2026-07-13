package spectre

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SpectreModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SpectreModule) ID() string   { return "spectre" }
func (m *SpectreModule) Name() string { return "Spectre - Hardware & Physical Attack Module" }
func (m *SpectreModule) Description() string {
	return "Air-gap exfiltration testing, SDR signal analysis, CDN cache poisoning, side-channel attack vectors"
}
func (m *SpectreModule) Severity() models.Severity { return models.Critical }

func (m *SpectreModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SpectreModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkAirgap(ctx, target)...)
	findings = append(findings, m.checkSDR(ctx, target)...)
	findings = append(findings, m.checkCacheGhost(ctx, target)...)
	findings = append(findings, m.checkSidechannel(ctx, target)...)

	return findings, nil
}

func (m *SpectreModule) checkAirgap(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	acousticPaths := []string{
		"/audio", "/audio/play", "/api/audio",
		"/sound", "/sound/play", "/api/sound",
		"/ultrasonic", "/api/ultrasonic",
		"/speaker", "/api/speaker",
	}

	for _, path := range acousticPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		for _, check := range []string{"audio", "sound", "speaker", "frequency",
			"ultrasonic", "wav", "mp3", "pcm", "audio/wav",
			"audio/mpeg", "media", "microphone",
			"web audio", "audiocontext", "oscillator"} {
			if strings.Contains(respBody, check) ||
				strings.Contains(strings.ToLower(fmt.Sprintf("%v", resp.Headers)), check) {
				findings = append(findings, &models.Finding{
					Title:       "Spectre - Airgap: Audio/Sound Endpoint Detected",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Audio endpoint found: %s (matched: %s)", path, check),
					Description: fmt.Sprintf("Audio endpoint at %s. Can be used for ultrasonic data exfiltration from air-gapped systems using high-frequency sound modulation.", path),
					Remediation: "Disable audio output on air-gapped systems. Use acoustic dampening. Monitor for unusual audio activity. Implement host-based audio access control.",
					CWEID:       "CWE-200",
					ModuleID:    "spectre",
				})
				break
			}
		}
	}

	brightnessPaths := []string{
		"/api/screen/brightness", "/api/display/brightness",
		"/screen/brightness", "/display/brightness",
		"/api/monitor/brightness", "/api/video/brightness",
	}

	for _, path := range brightnessPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		headers := map[string]string{"Content-Type": "application/json"}
		payloads := []string{
			`{"brightness":0}`,
			`{"brightness":100}`,
			`{"level":"high"}`,
			`{"intensity":"maximum"}`,
		}

		for _, p := range payloads {
			resp, err := m.client.DoRaw("POST", fullURL, headers, p)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				findings = append(findings, &models.Finding{
					Title:       "Spectre - Airgap: Screen Brightness Modulation",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Payload:     p,
					Evidence:    fmt.Sprintf("Brightness control accessible (status: %d) via %s", resp.StatusCode, path),
					Description: fmt.Sprintf("Screen brightness control accessible at %s. Can be used for optical data exfiltration by modulating screen brightness to binary signals.", path),
					Remediation: "Disable programmatic brightness control on sensitive systems. Use hardware switches for display control. Monitor for rapid brightness changes.",
					CWEID:       "CWE-200",
					ModuleID:    "spectre",
				})
				break
			}
		}
	}

	emPaths := []string{
		"/api/power", "/api/battery", "/api/power/status",
		"/power", "/battery", "/power/consumption",
		"/api/fan", "/api/cpu/power", "/api/gpu/power",
	}

	for _, path := range emPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		for _, check := range []string{"power", "battery", "consumption", "watt",
			"voltage", "current", "cpu_freq", "frequency_mhz",
			"fan_speed", "temperature", "thermal"} {
			if strings.Contains(respBody, check) {
				findings = append(findings, &models.Finding{
					Title:       "Spectre - Airgap: EM Emanation / Power Side-Channel",
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Power/EM endpoint found: %s (matched: %s)", path, check),
					Description: fmt.Sprintf("Power management endpoint at %s. Power consumption data can be used for electromagnetic emanation analysis, leaking data via power draw variations.", path),
					Remediation: "Use power filters and Faraday cages for sensitive systems. Implement constant-power operation modes. Monitor for anomalous power patterns.",
					CWEID:       "CWE-200",
					ModuleID:    "spectre",
				})
				break
			}
		}
	}

	return findings
}

func (m *SpectreModule) checkSDR(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	sdrPaths := []string{
		"/api/radio", "/api/sdr", "/api/wireless",
		"/radio", "/sdr", "/wireless",
		"/api/bluetooth", "/api/wifi", "/api/nfc",
		"/bluetooth", "/wifi", "/nfc",
		"/api/rf", "/rf", "/api/frequency",
		"/api/spectrum", "/spectrum",
		"/api/antenna", "/antenna",
	}

	for _, path := range sdrPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		for _, check := range []string{"radio", "sdr", "frequency", "rf",
			"bluetooth", "wifi", "nfc", "wireless",
			"antenna", "transceiver", "transmit",
			"receive", "spectrum", "iq data",
			"signal", "modulation", "demodulate",
			"freq", "mhz", "ghz", "band"} {
			if strings.Contains(respBody, check) ||
				strings.Contains(strings.ToLower(fmt.Sprintf("%v", resp.Headers)), check) {
				findings = append(findings, &models.Finding{
					Title:       "Spectre - SDR: Radio/Wireless Endpoint Detected",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("SDR/wireless endpoint found: %s (matched: %s)", path, check),
					Description: fmt.Sprintf("Software-defined radio endpoint at %s. Can be used for signal interception, replay attacks, or injecting malicious radio signals.", path),
					Remediation: "Disable unnecessary radio interfaces. Use encrypted radio protocols. Implement signal authentication. Monitor for unauthorized radio activity.",
					CWEID:       "CWE-200",
					ModuleID:    "spectre",
				})
				break
			}
		}
	}

	replayPaths := []string{
		"/api/rf/send", "/api/radio/transmit",
		"/api/rf/transmit", "/api/sdr/send",
		"/api/wireless/send", "/api/bluetooth/send",
		"/api/rf/replay", "/api/radio/replay",
	}

	for _, path := range replayPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		headers := map[string]string{"Content-Type": "application/json"}

		replayTests := []string{
			`{"frequency":433920000,"data":"AAAA","modulation":"ASK"}`,
			`{"frequency":315000000,"data":"test","modulation":"OOK"}`,
			`{"frequency":868000000,"data":"01010101","modulation":"FSK"}`,
		}

		for _, rt := range replayTests {
			resp, err := m.client.DoRaw("POST", fullURL, headers, rt)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 202 {
				findings = append(findings, &models.Finding{
					Title:       "Spectre - SDR: Replay Attack Interface",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Payload:     rt,
					Evidence:    fmt.Sprintf("RF signal transmission possible (status: %d) via %s", resp.StatusCode, path),
					Description: fmt.Sprintf("RF signal replay/transmission endpoint at %s. Enables replay attacks against wireless protocols, key fobs, and IoT devices.", path),
					Remediation: "Disable RF transmission APIs. Implement cryptographic authentication for all wireless commands. Use rolling codes for key fobs.",
					CWEID:       "CWE-294",
					ModuleID:    "spectre",
				})
				break
			}
		}
	}

	return findings
}

func (m *SpectreModule) checkCacheGhost(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	poisonHeaders := []struct {
		name  string
		value string
	}{
		{name: "X-Forwarded-Host", value: "evil.com"},
		{name: "X-Forwarded-Scheme", value: "http"},
		{name: "X-Original-URL", value: "/admin"},
		{name: "X-Rewrite-URL", value: "/evil.js"},
		{name: "X-HTTP-Method-Override", value: "PUT"},
		{name: "X-Forwarded-For", value: "127.0.0.1"},
		{name: "X-Real-IP", value: "127.0.0.1"},
		{name: "X-Originating-IP", value: "127.0.0.1"},
	}

	for _, ph := range poisonHeaders {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		headers := map[string]string{ph.name: ph.value}
		resp, err := m.client.DoRaw("GET", target.URL, headers, "")
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 0 {
			for _, check := range []string{ph.value, "evil.com", "/admin", "/evil.js", "127.0.0.1"} {
				if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("Spectre - CDN Cache Poisoning (%s)", ph.name),
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         target.URL,
						Payload:     fmt.Sprintf("%s: %s", ph.name, ph.value),
						Evidence:    fmt.Sprintf("Header %s reflected/influenced response (matched: %s)", ph.name, check),
						Description: fmt.Sprintf("Header %s influences response. Can be used for cache poisoning (CP-DOS), poisoning CDN with malicious content to serve to all users.", ph.name),
						Remediation: "Ignore proxy headers from untrusted sources. Normalize headers at edge. Use strict header validation. Implement Vary headers correctly.",
						CWEID:       "CWE-644",
						ModuleID:    "spectre",
					})
					break
				}
			}
		}
	}

	deceptionPaths := []string{
		"/api/user/profile",
		"/api/account/details",
		"/admin/config",
		"/.env",
		"/config.json",
		"/api/users/me",
		"/api/session",
		"/private/key",
	}

	staticExtensions := []string{".css", ".js", ".jpg", ".png", ".gif", ".ico", ".pdf", ".txt", ".xml", ".svg", ".webp"}

	for _, base := range deceptionPaths {
		for _, ext := range staticExtensions {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			fullURL := strings.TrimRight(target.URL, "/") + base + ext
			resp, err := m.client.Get(fullURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && len(resp.Body) > 0 {
				bodyLower := strings.ToLower(resp.Body)
				if strings.Contains(bodyLower, "password") || strings.Contains(bodyLower, "token") ||
					strings.Contains(bodyLower, "secret") || strings.Contains(bodyLower, "api_key") ||
					strings.Contains(bodyLower, "session") || strings.Contains(bodyLower, "auth") ||
					strings.Contains(bodyLower, "jwt") || strings.Contains(bodyLower, "bearer") {
					findings = append(findings, &models.Finding{
						Title:       "Spectre - Cache Deception (Sensitive Data Cached)",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Sensitive data served with static extension %s (status: %d)", ext, resp.StatusCode),
						Description: fmt.Sprintf("Sensitive endpoint %s serves content with static extension %s. CDN will cache this, exposing sensitive data to all users.", base, ext),
						Remediation: "Configure CDN to cache only by content-type. Use 'X-Origin' headers. Implement Cache-Control: private for sensitive endpoints. Use cache keys based on cookies.",
						CWEID:       "CWE-524",
						ModuleID:    "spectre",
					})
				}
			}
		}
	}

	cpdosPaths := []string{
		"/", "/api", "/api/v1",
		"/api/health", "/api/status",
		"/index.html", "/main.js",
	}

	for _, path := range cpdosPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path

		headers := map[string]string{
			"X-Forwarded-Host":   "cdn.example.com",
			"X-Forwarded-Scheme": "https",
		}
		resp, err := m.client.DoRaw("GET", fullURL, headers, "")
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && (strings.Contains(resp.Body, "cdn.example.com") ||
			strings.Contains(resp.Body, "X-Forwarded-Host") ||
			strings.Contains(resp.Body, "X-Forwarded") ||
			strings.Contains(resp.Body, "cdn")) {
			_ = resp
			findings = append(findings, &models.Finding{
				Title:       "Spectre - CP-DOS (Cache Poisoning Denial of Service)",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Payload:     "X-Forwarded-Host header manipulation",
				Evidence:    fmt.Sprintf("CP-DOS vector: header reflected in response at %s", path),
				Description: fmt.Sprintf("Cache poisoning DoS at %s. Attacker can poison CDN cache with malicious or empty content, causing denial of service for all users until cache expires.", path),
				Remediation: "Ignore or validate X-Forwarded-Host. Use host header for URL generation. Implement cache key separation. Use short TTLs for dynamic content.",
				CWEID:       "CWE-644",
				ModuleID:    "spectre",
			})
		}
	}

	return findings
}

func (m *SpectreModule) checkSidechannel(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	timingPaths := []string{
		"/api/login", "/api/auth", "/api/verify",
		"/login", "/auth/login", "/api/authenticate",
		"/api/user/exists", "/api/check-email",
		"/api/reset-password", "/api/forgot-password",
	}

	for _, path := range timingPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		slowPayloads := []string{
			"admin' OR '1'='1",
			"admin\" OR \"1\"=\"1",
			"admin' OR SLEEP(0)--",
			"guest' AND '1'='1",
			"test' AND 1=1--",
			"user' UNION SELECT * FROM users--",
		}

		for _, payload := range slowPayloads {
			fullURL := strings.TrimRight(target.URL, "/") + path
			testURL := fullURL + "?username=" + payload + "&password=test"

			start := timeNow()
			resp, err := m.client.Get(testURL)
			elapsed := timeSince(start)
			if err != nil {
				continue
			}
			_ = resp

			if elapsed > 1.5 {
				baselineURL := fullURL + "?username=nonexistent&password=wrong"
				baseStart := timeNow()
				m.client.Get(baselineURL)
				baselineElapsed := timeSince(baseStart)

				if elapsed > baselineElapsed+0.5 {
					findings = append(findings, &models.Finding{
						Title:       "Spectre - Side-Channel: Timing Attack Vector",
						Severity:    models.Medium,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Timing difference detected: %.2fs vs baseline %.2fs", elapsed, baselineElapsed),
						Description: fmt.Sprintf("Timing variation at %s suggests authentication endpoint processes payloads differently. Can be used for user enumeration and password brute-forcing via timing side-channels.", path),
						Remediation: "Use constant-time comparison functions. Implement request jitter. Ensure consistent response timing regardless of input validity.",
						CWEID:       "CWE-208",
						ModuleID:    "spectre",
					})
					break
				}
			}
		}
	}

	enumPaths := []string{
		"/api/user/exists", "/api/user/check",
		"/api/check-username", "/api/email/check",
		"/api/register/check", "/api/signup/check",
	}

	for _, path := range enumPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		existingResp, _ := m.client.Get(fullURL + "?email=admin@test.com")
		nonexistingResp, _ := m.client.Get(fullURL + "?email=nonexistent@test.com")

		if existingResp != nil && nonexistingResp != nil {
			if (existingResp.StatusCode != nonexistingResp.StatusCode) ||
				(len(existingResp.Body) != len(nonexistingResp.Body)) ||
				(existingResp.Body != nonexistingResp.Body) {
				findings = append(findings, &models.Finding{
					Title:       "Spectre - Side-Channel: User Enumeration",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Different responses for existing vs non-existing users (status: %d vs %d)", existingResp.StatusCode, nonexistingResp.StatusCode),
					Description: fmt.Sprintf("User enumeration possible at %s. Different responses reveal whether a user exists, enabling targeted attacks.", path),
					Remediation: "Return consistent responses for all user existence checks. Use generic error messages. Implement rate limiting on authentication endpoints.",
					CWEID:       "CWE-203",
					ModuleID:    "spectre",
				})
			}
		}
	}

	errorDetailPaths := []string{
		"/api/login", "/api/auth", "/api/verify",
		"/api/error", "/api/debug", "/api/trace",
	}

	for _, path := range errorDetailPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL + "?debug=true")
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		verboseIndicators := []string{
			"stack trace", "stacktrace", "at ", "in ",
			"exception", "error code", "error number",
			"line ", "file ", "debug", "trace",
			"traceback", "call stack", "function ",
			"memory address", "0x", "nil pointer",
			"segmentation fault", "segfault",
		}

		matchCount := 0
		for _, ind := range verboseIndicators {
			if strings.Contains(respBody, ind) {
				matchCount++
			}
		}

		if matchCount >= 2 {
			findings = append(findings, &models.Finding{
				Title:       "Spectre - Side-Channel: Verbose Error / Stack Trace Leak",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Verbose error details revealed (matched %d indicators)", matchCount),
				Description: fmt.Sprintf("Verbose error details at %s leak internal information useful for reconnaissance and precision attacks.", path),
				Remediation: "Disable detailed error messages in production. Use generic error responses. Log detailed errors server-side only.",
				CWEID:       "CWE-209",
				ModuleID:    "spectre",
			})
		}
	}

	return findings
}

var timeNow = func() time.Time {
	return time.Now()
}

var timeSince = func(t time.Time) float64 {
	return time.Since(t).Seconds()
}

func init() {
	engine.GetRegistry().Register(&SpectreModule{})
}
