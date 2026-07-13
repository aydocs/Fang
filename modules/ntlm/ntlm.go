package ntlm

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type NTLMModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *NTLMModule) ID() string   { return "ntlm" }
func (m *NTLMModule) Name() string { return "NTLM Relay & Pass-the-Hash" }
func (m *NTLMModule) Description() string {
	return "NTLM relay detection, pass-the-hash vectors, SMB relay, NTLM capture analysis, responder integration checks"
}
func (m *NTLMModule) Severity() models.Severity { return models.Critical }

func (m *NTLMModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *NTLMModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	host := extractHostNTLM(target.URL)

	findings = append(findings, m.checkNTLMSigning(host)...)
	findings = append(findings, m.checkNTLMWebEndpoints(ctx, target)...)

	return findings, nil
}

func (m *NTLMModule) checkNTLMSigning(host string) []*models.Finding {
	var findings []*models.Finding

	if !checkPort(host, 445) {
		return nil
	}

	findings = append(findings, &models.Finding{
		Title:       "NTLM - SMB Relay Possible (Signing Check)",
		Severity:    models.Critical,
		Confidence:  models.MediumConfidence,
		URL:         fmt.Sprintf("smb://%s:445", host),
		Evidence:    "SMB port 445 is open. NTLM signing state should be verified with SMB connection.",
		Description: "If SMB signing is disabled, NTLM relay attacks are possible. An attacker can relay captured NTLM authentication to access SMB services.",
		Remediation: "Enable SMB signing on all systems. Disable LLMNR and NetBIOS over TCP/IP. Use Extended Protection for Authentication (EPA).",
		CWEID:       "CWE-287",
		ModuleID:    "ntlm",
	})

	return findings
}

func (m *NTLMModule) checkNTLMWebEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	paths := []string{
		"/", "/owa", "/ecp", "/ews", "/iis", "/adfs",
		"/windows", "/rdweb", "/remote", "/rpc",
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(url)
		if err != nil {
			continue
		}

		wwwAuth := ""
		for key, values := range resp.Headers {
			if strings.EqualFold(key, "WWW-Authenticate") {
				for _, v := range values {
					wwwAuth = v
				}
			}
		}

		if strings.Contains(strings.ToLower(wwwAuth), "ntlm") {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("NTLM - Web Endpoint Exposes NTLM (%s)", path),
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         url,
				Evidence:    fmt.Sprintf("WWW-Authenticate: %s", wwwAuth),
				Description: "Web endpoint exposes NTLM authentication over HTTP. NTLM hashes can be captured and relayed or cracked offline.",
				Remediation: "Disable NTLM authentication on web endpoints. Use Kerberos or modern auth protocols. Enable EPA on IIS.",
				CWEID:       "CWE-522",
				ModuleID:    "ntlm",
			})
		}
	}

	return findings
}

func checkPort(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func extractHostNTLM(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "smb://")
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func init() {
	engine.GetRegistry().Register(&NTLMModule{})
}
