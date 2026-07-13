package cmdi

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

type CMDIModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *CMDIModule) ID() string   { return "cmdi" }
func (m *CMDIModule) Name() string { return "OS Command Injection Scanner" }
func (m *CMDIModule) Description() string {
	return "Detects OS command injection including blind time-based and output-based detection"
}
func (m *CMDIModule) Severity() models.Severity { return models.Critical }

func (m *CMDIModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *CMDIModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
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
		paramNames = []string{"cmd", "command", "exec", "execute", "ping", "host", "ip", "url", "file", "path", "query", "search", "input", "data", "param"}
	}

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
		baselineStart := time.Now()
		baselineResp, err := m.client.Get(baselineURL)
		baselineTime := time.Since(baselineStart).Seconds()
		if err != nil {
			continue
		}

		for _, up := range inject.CMDIUnixPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
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
						ModuleID:    "cmdi",
					})
					goto nextParam
				}
			}
		}

		for _, wp := range inject.CMDIWindowsPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
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
						ModuleID:    "cmdi",
					})
					goto nextParam
				}
			}
		}

		for _, tp := range inject.CMDITimePayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
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
					ModuleID:    "cmdi",
				})
				goto nextParam
			}
		}

	nextParam:
	}

	return findings, nil
}

func (m *CMDIModule) buildURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func init() {
	engine.GetRegistry().Register(&CMDIModule{})
}
