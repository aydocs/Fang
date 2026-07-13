package ssrf

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

type SSRFModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SSRFModule) ID() string   { return "ssrf" }
func (m *SSRFModule) Name() string { return "Server-Side Request Forgery Scanner" }
func (m *SSRFModule) Description() string {
	return "Detects SSRF via internal IPs, cloud metadata endpoints, and file protocol"
}
func (m *SSRFModule) Severity() models.Severity { return models.Critical }

func (m *SSRFModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SSRFModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
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
		paramNames = []string{"url", "uri", "link", "src", "dest", "redirect", "redirect_uri", "return", "next", "path", "file", "document", "folder", "image", "img", "load", "fetch"}
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
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		for _, ip := range inject.SSRFInternalIPs() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildURL(parsed, params, paramName, ip)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode != baselineResp.StatusCode || abs(len(resp.Body)-len(baselineResp.Body)) > 100 {
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
						ModuleID:    "ssrf",
					})
					goto nextParam
				}
			}
		}

		for _, cm := range inject.SSRFCloudMetadataEndpoints() {
			select {
			case <-ctx.Done():
				return findings, nil
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
					ModuleID:    "ssrf",
				})
				goto nextParam
			}
		}

		for _, proto := range inject.SSRFProtocols() {
			select {
			case <-ctx.Done():
				return findings, nil
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
					ModuleID:    "ssrf",
				})
				goto nextParam
			}
		}

		if m.cfg.Timeout > time.Second*3 {
			testURL := m.buildURL(parsed, params, paramName, "http://10.255.255.1:8080/")
			start := time.Now()
			resp, err := m.client.Get(testURL)
			elapsed := time.Since(start)
			_ = resp
			if err != nil && elapsed > time.Second*2 {
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
					ModuleID:    "ssrf",
				})
			}
		}

	nextParam:
	}

	return findings, nil
}

func (m *SSRFModule) buildURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func init() {
	engine.GetRegistry().Register(&SSRFModule{})
}
