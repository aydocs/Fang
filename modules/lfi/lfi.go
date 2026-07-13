package lfi

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type LFIModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *LFIModule) ID() string   { return "lfi" }
func (m *LFIModule) Name() string { return "Local File Inclusion Scanner" }
func (m *LFIModule) Description() string {
	return "Detects LFI via path traversal, PHP wrappers, null byte injection, and log poisoning"
}
func (m *LFIModule) Severity() models.Severity { return models.Critical }

func (m *LFIModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *LFIModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"file", "page", "include", "path", "doc", "folder", "root", "pg", "style", "pdf", "template", "php_path", "document", "category", "load"}
	}

paramLoop:
	for _, paramName := range paramNames {
		select {
		case <-ctx.Done():
			return findings, nil
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
				return findings, nil
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
						ModuleID:    "lfi",
					})
					continue paramLoop
				}
			}
		}

		for _, pw := range inject.LFIPHPWrappers() {
			select {
			case <-ctx.Done():
				return findings, nil
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
						ModuleID:    "lfi",
					})
					continue paramLoop
				}
			}
		}

		for _, ep := range inject.LFIErrorPatterns() {
			select {
			case <-ctx.Done():
				return findings, nil
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
					ModuleID:    "lfi",
				})
				break
			}
		}

		logTestURL := m.buildURL(parsed, params, paramName, "../../../var/log/apache2/access.log")
		lresp, lerr := m.client.Get(logTestURL)
		if lerr != nil {
			continue
		}

		if strings.Contains(lresp.Body, "GET /") || strings.Contains(lresp.Body, "HTTP/1.1") || strings.Contains(lresp.Body, "apache") || strings.Contains(lresp.Body, "nginx") {
			findings = append(findings, &models.Finding{
				Title:       "LFI - Log Poisoning Possible",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         logTestURL,
				Parameter:   paramName,
				Payload:     "../../../var/log/apache2/access.log",
				Evidence:    "Log file contents found in response",
				Description: fmt.Sprintf("Parameter '%s' can read log files, enabling log poisoning attacks.", paramName),
				Remediation: "Restrict file access permissions. Disable PHP allow_url_include. Use chroot or jail.",
				CWEID:       "CWE-22",
				ModuleID:    "lfi",
			})
		}

	}

	return findings, nil
}

func (m *LFIModule) buildURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func init() {
	engine.GetRegistry().Register(&LFIModule{})
}
