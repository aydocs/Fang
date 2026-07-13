package evasion

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type EvasionModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *EvasionModule) ID() string   { return "evasion" }
func (m *EvasionModule) Name() string { return "WAF/AV Bypass & Evasion Testing" }
func (m *EvasionModule) Description() string {
	return "WAF bypass techniques, AV/EDR bypass detection, rate limit bypass, fingerprint manipulation"
}
func (m *EvasionModule) Severity() models.Severity { return models.High }

func (m *EvasionModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

type wafBypassTest struct {
	Name    string
	Headers map[string]string
}

var wafBypassTests = []wafBypassTest{
	{
		Name: "Cloudflare - X-Forwarded-For Bypass",
		Headers: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Real-IP":        "127.0.0.1",
			"CF-Connecting-IP": "127.0.0.1",
		},
	},
	{
		Name: "Cloudflare - True-Client-IP",
		Headers: map[string]string{
			"True-Client-IP":   "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
		},
	},
	{
		Name: "AWS WAF - X-Forwarded-For Origin",
		Headers: map[string]string{
			"X-Forwarded-For":  "192.168.1.1",
			"X-Forwarded-Host": "internal.admin",
		},
	},
	{
		Name: "ModSecurity - CRS Bypass",
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
			"Accept":       "text/html,application/xhtml+xml",
		},
	},
	{
		Name: "Imperva - Incapsula Bypass",
		Headers: map[string]string{
			"X-Incap-Client-IP":  "127.0.0.1",
			"X-Incap-Request-ID": "bypass",
			"X-Client-IP":        "127.0.0.1",
		},
	},
	{
		Name: "F5 ASM - BigIP Bypass",
		Headers: map[string]string{
			"X-Forwarded-For":   "127.0.0.1",
			"X-F5-Auth":         "true",
			"X-Forwarded-Proto": "https",
		},
	},
	{
		Name: "Akamai - True-Client-IP Bypass",
		Headers: map[string]string{
			"True-Client-IP":   "127.0.0.1",
			"X-True-Client-IP": "127.0.0.1",
		},
	},
	{
		Name: "Parameter Pollution - Duplicate",
		Headers: map[string]string{
			"X-Forwarded-For-1": "127.0.0.1",
			"X-Forwarded-For-2": "192.168.1.1",
			"X-Forwarded-For-3": "10.0.0.1",
		},
	},
	{
		Name: "Unicode Normalization Bypass",
		Headers: map[string]string{
			"X-Forwarded-For": "127．0．0．1",
		},
	},
	{
		Name: "Chunked Transfer Encoding",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
			"Content-Length":    "0",
		},
	},
	{
		Name: "HTTP Method Override",
		Headers: map[string]string{
			"X-HTTP-Method-Override": "POST",
			"X-HTTP-Method":          "TRACE",
			"X-Method-Override":      "PUT",
		},
	},
	{
		Name: "Hop-by-Hop Header Smuggling",
		Headers: map[string]string{
			"Connection": "close, X-Internal",
			"X-Internal": "true",
		},
	},
	{
		Name: "Range Header Smuggling",
		Headers: map[string]string{
			"Range": "bytes=0-18446744073709551615",
		},
	},
	{
		Name: "Content-Type Confusion",
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; param=value",
		},
	},
	{
		Name: "Tab Separated Headers",
		Headers: map[string]string{
			"X-Forwarded-For": "127.0.0.1",
		},
	},
}

type avBypassIndicator struct {
	Name       string
	Indicators []string
}

var avBypassIndicators = []avBypassIndicator{
	{
		Name: "AMSI Bypass",
		Indicators: []string{
			"amsi", "amsiscanbuffer", "amsiopen", "amsidynamic",
			"amsipatch", "amsibypass", "a m s i", "a.m.s.i",
			"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
			"HKLM:\\SOFTWARE\\Microsoft\\AMSI",
		},
	},
	{
		Name: "ETW Patching",
		Indicators: []string{
			"etw", "etweventwrite", "etwpatching", "ntdll!etw",
			"etwpatch", "etw bypass", "event tracing",
			"EtwEventWrite", "EtwEventWriteFull",
		},
	},
	{
		Name: "NTDLL Unhooking",
		Indicators: []string{
			"ntdll", "unhook", "ntdll.dll", "ntdllunhook",
			"ntdll unhook", "fresh ntdll", "ntsuspendprocess",
			"ZwUnmapViewOfSection", "LdrLoadDll",
		},
	},
	{
		Name: "Direct Syscall",
		Indicators: []string{
			"syscall", "direct syscall", "s Mc", "syswhispers",
			"hells gate", "hellgate", "halos gate", "tartarus gate",
			"syscall stub", "ret2dll", "ret 2 dll",
		},
	},
	{
		Name: "Process Injection",
		Indicators: []string{
			"createprocess", "createremotethread", "virtualallocex",
			"writeprocessmemory", "queueuserapc", "ntcreatethreadex",
			"openprocess", "ntopenprocess",
		},
	},
	{
		Name: "DLL Injection",
		Indicators: []string{
			"loadlibrary", "ldrloaddll", "dll injection",
			"reflectivedll", "dll hijack", "dll sideload",
		},
	},
	{
		Name: "Process Hollowing",
		Indicators: []string{
			"hollow", "process hollowing", "ntunmapviewofsection",
			"zwunmapviewofsection", "runpe",
		},
	},
	{
		Name: "Token Stealing",
		Indicators: []string{
			"duplicatetoken", "impersonateloggedonuser",
			"openthreadtoken", "token stealing", "seprivilege",
			"adjusttokenprivileges", "sebackupprivilege",
		},
	},
	{
		Name: "EDR Detection",
		Indicators: []string{
			"edr", "endpoint detection", "ngav", "next gen av",
			"windows defender", "mse", "mpengine",
			"sense", "mssense", "wscsvc",
		},
	},
}

func (m *EvasionModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	wafFindings := m.scanWAFBypass(ctx, target)
	findings = append(findings, wafFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	avFindings := m.scanAVBypass(ctx, target)
	findings = append(findings, avFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	rateFindings := m.scanRateLimit(ctx, target)
	findings = append(findings, rateFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	fpFindings := m.scanFingerprint(ctx, target)
	findings = append(findings, fpFindings...)

	return findings, nil
}

func (m *EvasionModule) scanWAFBypass(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	baselineResp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}
	baselineSize := len(baselineResp.Body)
	baselineStatus := baselineResp.StatusCode

	for _, test := range wafBypassTests {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		req := fanghttp.NewRequest(http.MethodGet, target.URL)
		for k, v := range test.Headers {
			req.Headers[k] = v
		}
		if len(test.Headers) > 1 {
			multiValHeaders := []string{"X-Forwarded-For", "X-HTTP-Method-Override"}
			for _, h := range multiValHeaders {
				if val, ok := test.Headers[h]; ok {
					req.Headers[h] = val
				}
			}
		}

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		respSize := len(resp.Body)
		sizeDiff := respSize - baselineSize
		if sizeDiff < 0 {
			sizeDiff = -sizeDiff
		}

		if resp.StatusCode != baselineStatus || sizeDiff > baselineSize/5 {
			headerStr := ""
			for k, v := range test.Headers {
				headerStr += fmt.Sprintf("%s: %s ", k, v)
			}

			findings = append(findings, m.makeFinding(
				fmt.Sprintf("WAF Bypass - %s", test.Name),
				models.Medium, models.MediumConfidence,
				target.URL, "", headerStr,
				fmt.Sprintf("Status: %d→%d, Size: %d→%d (%s)", baselineStatus, resp.StatusCode, baselineSize, respSize, test.Name),
				"WAF bypass technique produced different response.",
				"Implement defense-in-depth. Use multiple WAF rulesets and server-side validation.",
				"CWE-290",
			))
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *EvasionModule) scanAVBypass(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := strings.ToLower(resp.Body)

	for _, indicator := range avBypassIndicators {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		matched := []string{}
		for _, pattern := range indicator.Indicators {
			if strings.Contains(body, strings.ToLower(pattern)) {
				matched = append(matched, pattern)
			}
		}

		if len(matched) > 0 {
			severity := models.High
			confidence := models.MediumConfidence

			switch indicator.Name {
			case "AMSI Bypass":
				severity = models.Critical
				confidence = models.HighConfidence
			case "ETW Patching":
				severity = models.Critical
				confidence = models.HighConfidence
			case "Direct Syscall":
				severity = models.High
			case "NTDLL Unhooking":
				severity = models.High
			case "Process Injection":
				severity = models.Critical
			case "DLL Injection":
				severity = models.High
			case "Process Hollowing":
				severity = models.Critical
			case "Token Stealing":
				severity = models.Critical
			}

			findings = append(findings, m.makeFinding(
				fmt.Sprintf("AV/EDR Bypass - %s", indicator.Name),
				severity, confidence,
				target.URL, "", strings.Join(matched, ", "),
				fmt.Sprintf("AV/EDR bypass indicators found: %s", strings.Join(matched, ", ")),
				"AV/EDR bypass technique '%s' indicators detected in response content.",
				"Investigate the source for potential malware. Deploy advanced endpoint detection solutions.",
				"CWE-912",
			))
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *EvasionModule) scanRateLimit(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	burstSize := 20
	successCount := 0
	rateLimited := false

	for i := 0; i < burstSize; i++ {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		waitMs := rng.Intn(50)
		time.Sleep(time.Duration(waitMs) * time.Millisecond)

		parsed, _ := url.Parse(target.URL)
		query := ""
		if parsed != nil {
			query = parsed.RawQuery
		}
		var testURL string
		if query != "" {
			testURL = target.URL + "&_t=" + fmt.Sprintf("%d", time.Now().UnixNano())
		} else {
			testURL = target.URL + "?_t=" + fmt.Sprintf("%d", time.Now().UnixNano())
		}

		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			successCount++
		}

		if resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == 429 ||
			resp.StatusCode == 503 ||
			resp.StatusCode == 403 {

			retryAfter := resp.Headers.Get("Retry-After")
			findings = append(findings, m.makeFinding(
				"Rate Limit Detected",
				models.Info, models.HighConfidence,
				target.URL, "", fmt.Sprintf("status=%d, retry-after=%s", resp.StatusCode, retryAfter),
				fmt.Sprintf("Rate limiting triggered after %d requests (HTTP %d)", i+1, resp.StatusCode),
				"Rate limiting detected at '%s' after %d requests.",
				"Rate limiting is properly configured. Test if bypass is possible via IP rotation or header manipulation.",
				"CWE-770",
			))
			rateLimited = true
			break
		}
	}

	if !rateLimited && successCount >= burstSize-2 {
		findings = append(findings, m.makeFinding(
			"Rate Limit Bypass Possible",
			models.High, models.MediumConfidence,
			target.URL, "", fmt.Sprintf("burst=%d, success=%d", burstSize, successCount),
			fmt.Sprintf("All %d rapid requests succeeded - no rate limiting detected", burstSize),
			"No rate limiting was detected for %d rapid requests against '%s'.",
			"Implement rate limiting with graduated delays, IP-based throttling, and CAPTCHA for excessive requests.",
			"CWE-770",
		))
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *EvasionModule) scanFingerprint(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	baselineResp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	userAgents := []string{
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
		"curl/7.68.0",
		"Wget/1.21",
		"Python-urllib/3.10",
		"Go-http-client/2.0",
		"Nmap Scripting Engine",
		"sqlmap/1.6",
		"Nikto/2.1.6",
		"FANG-Scanner/1.0",
	}

	headersVariants := []map[string]string{
		{"Accept": "text/plain,application/json"},
		{"Accept-Language": "en-US,en;q=0.9"},
		{"Accept-Encoding": "gzip, deflate, br"},
		{"Cache-Control": "no-cache, no-store"},
		{"X-Forwarded-For": "10.0.0.1"},
		{"X-Requested-With": "XMLHttpRequest"},
		{"Via": "1.1 proxy.example.com"},
		{"X-Cache": "MISS"},
		{"DNT": "1"},
	}

	baselineBody := ""
	if baselineResp != nil {
		baselineBody = baselineResp.Body
	}
	baselineSize := len(baselineBody)

	for _, ua := range userAgents {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		req := fanghttp.NewRequest(http.MethodGet, target.URL).WithHeader("User-Agent", ua)
		for _, h := range headersVariants {
			for k, v := range h {
				req.Headers[k] = v
				break
			}
		}

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		respSize := len(resp.Body)
		sizeDiff := respSize - baselineSize
		if sizeDiff < 0 {
			sizeDiff = -sizeDiff
		}

		if sizeDiff > baselineSize/10 && sizeDiff > 100 {
			uaShort := ua
			if len(uaShort) > 50 {
				uaShort = uaShort[:50] + "..."
			}

			findings = append(findings, m.makeFinding(
				fmt.Sprintf("Fingerprint Manipulation - User-Agent: %s", uaShort),
				models.Low, models.MediumConfidence,
				target.URL, "", ua,
				fmt.Sprintf("Response changed by %d bytes with User-Agent: %s", sizeDiff, uaShort),
				"Different User-Agent strings produce varying responses at '%s', indicating fingerprint-based content delivery.",
				"Fingerprint-based content can be fingerprinted. Ensure consistent responses or use proper bot detection.",
				"CWE-200",
			))
			break
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *EvasionModule) makeFinding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
	return &models.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		URL:         urlStr,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: fmt.Sprintf(description, param),
		Remediation: remediation,
		CWEID:       cwe,
		ModuleID:    "evasion",
	}
}

func init() {
	engine.GetRegistry().Register(&EvasionModule{})
}
