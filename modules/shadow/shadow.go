package shadow

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ShadowModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ShadowModule) ID() string   { return "shadow" }
func (m *ShadowModule) Name() string { return "Shadow - C2 & Control Module" }
func (m *ShadowModule) Description() string {
	return "C2 panel detection, multi-protocol C2 server detection, malware agent endpoints, tunnel detection, beaconing pattern detection"
}
func (m *ShadowModule) Severity() models.Severity { return models.Critical }

func (m *ShadowModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *ShadowModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkPanel(ctx, target)...)
	findings = append(findings, m.checkC2Server(ctx, target)...)
	findings = append(findings, m.checkAgent(ctx, target)...)
	findings = append(findings, m.checkTunnel(ctx, target)...)
	findings = append(findings, m.checkBeacon(ctx, target)...)

	return findings, nil
}

func (m *ShadowModule) checkPanel(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	panelPaths := []string{
		"/panel", "/c2", "/admin/c2", "/dashboard", "/admin/dashboard",
		"/c2panel", "/c2-admin", "/c2/dashboard", "/server/panel",
		"/control", "/command", "/admin/panel", "/management",
		"/api/c2", "/api/panel", "/server/control", "/c2/control",
	}

	panelIndicators := []string{
		"c2 panel", "command & control", "c&c", "c2 server", "beacon",
		"agent", "botnet", "payload", "listener", "stager", "implant",
	}

panelLoop:
	for _, path := range panelPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if resp.StatusCode == 200 {
			for _, indicator := range panelIndicators {
				if strings.Contains(respBody, indicator) {
					severity := models.High
					if strings.Contains(respBody, "botnet") || strings.Contains(respBody, "implant") {
						severity = models.Critical
					}

					findings = append(findings, &models.Finding{
						Title:       "Shadow - C2 Panel Detected",
						Severity:    severity,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("C2 panel detected at %s (status: %d, matched: %s)", path, resp.StatusCode, indicator),
						Description: fmt.Sprintf("C2 control panel endpoint discovered at %s. Provides full C2 management interface for agents, beacons, and payloads.", path),
						Remediation: "Take down C2 infrastructure. Block panel IPs/domains. Report to threat intelligence platforms.",
						CWEID:       "CWE-284",
						ModuleID:    "shadow",
					})
					continue panelLoop
				}
			}

			if resp.BodyLength > 500 && len(resp.Headers["Set-Cookie"]) > 0 {
				findings = append(findings, &models.Finding{
					Title:       "Shadow - Potential C2 Panel Login",
					Severity:    models.Medium,
					Confidence:  models.LowConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Potential panel login at %s (status: %d, cookies: %v)", path, resp.StatusCode, len(resp.Headers["Set-Cookie"])),
					Description: fmt.Sprintf("Endpoint at %s returns a login page. May be C2 panel authentication.", path),
					Remediation: "Investigate endpoint. Block if confirmed as C2 infrastructure.",
					CWEID:       "CWE-284",
					ModuleID:    "shadow",
				})
			}
		}
	}

	authEndpoints := []string{"/api/login", "/api/auth", "/api/authenticate", "/api/panel/login", "/api/c2/login"}
	loginPayloads := []string{
		`{"username":"admin","password":"admin"}`,
		`{"user":"admin","pass":"admin"}`,
		`{"username":"root","password":"toor"}`,
	}

authLoop:
	for _, path := range authEndpoints {
		fullURL := strings.TrimRight(target.URL, "/") + path

		for _, lp := range loginPayloads {
			resp, err := m.client.Post(fullURL, lp)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				findings = append(findings, &models.Finding{
					Title:       "Shadow - C2 Panel Auth Endpoint",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("C2 auth endpoint at %s (status: %d)", path, resp.StatusCode),
					Description: fmt.Sprintf("C2 panel authentication endpoint at %s. May accept default credentials.", path),
					Remediation: "Change all default credentials. Implement MFA. Use strong password policies.",
					CWEID:       "CWE-284",
					ModuleID:    "shadow",
				})
				continue authLoop
			}
		}
	}

	return findings
}

func (m *ShadowModule) checkC2Server(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	c2Protocols := []struct {
		name       string
		path       string
		method     string
		body       string
		headers    map[string]string
		indicators []string
	}{
		{
			name:       "gRPC C2",
			path:       "/grpc.c2/Command",
			method:     "POST",
			body:       `\x00\x00\x00\x00\x05c2.Command/Execute`,
			headers:    map[string]string{"Content-Type": "application/grpc", "Accept": "application/grpc"},
			indicators: []string{"grpc", "c2"},
		},
		{
			name:       "HTTPS C2",
			path:       "/c2/command",
			method:     "POST",
			body:       `{"cmd":"whoami","id":"test-beacon"}`,
			headers:    map[string]string{"Content-Type": "application/json"},
			indicators: []string{"command", "beacon", "task"},
		},
		{
			name:       "DoH C2",
			path:       "/dns-query",
			method:     "POST",
			body:       base64.StdEncoding.EncodeToString([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
			headers:    map[string]string{"Content-Type": "application/dns-message"},
			indicators: []string{"dns", "dns-message"},
		},
		{
			name:       "WebSocket C2",
			path:       "/ws/c2",
			method:     "GET",
			headers:    map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13"},
			indicators: []string{"websocket", "upgrade"},
		},
		{
			name:       "ICMP C2",
			path:       "/icmp",
			method:     "GET",
			indicators: []string{"icmp", "ping", "tunnel"},
		},
		{
			name:       "C2 Tasking",
			path:       "/tasks",
			method:     "GET",
			indicators: []string{"task", "command", "beacon", "job"},
		},
		{
			name:       "C2 Results",
			path:       "/results",
			method:     "POST",
			body:       `{"id":"beacon-1","output":"test"}`,
			headers:    map[string]string{"Content-Type": "application/json"},
			indicators: []string{"result", "output", "beacon"},
		},
	}

	for _, cp := range c2Protocols {
		fullURL := strings.TrimRight(target.URL, "/") + cp.path

		var resp *fanghttp.Response
		var err error

		if cp.method == "POST" {
			req := fanghttp.NewRequest("POST", fullURL)
			req.Body = cp.body
			for k, v := range cp.headers {
				req.Headers[k] = v
			}
			resp, err = m.client.Do(req)
		} else {
			if len(cp.headers) > 0 {
				resp, err = m.client.DoRaw(cp.method, fullURL, cp.headers, "")
			} else {
				resp, err = m.client.Get(fullURL)
			}
		}

		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		matched := false
		for _, indicator := range cp.indicators {
			if strings.Contains(respBody, indicator) || strings.Contains(strings.ToLower(resp.Status), indicator) {
				matched = true
				break
			}
		}

		if matched || resp.StatusCode == 200 || resp.StatusCode == 101 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Shadow - C2 Server Detected (%s)", cp.name),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("C2 server endpoint at %s (status: %d, protocol: %s)", cp.path, resp.StatusCode, cp.name),
				Description: fmt.Sprintf("Multi-protocol C2 server discovered at %s using %s. Potential for command dispatch, tasking, and data exfiltration.", cp.path, cp.name),
				Remediation: "Block C2 server IPs/domains. Implement network detection for C2 protocols. Use threat intelligence feeds.",
				CWEID:       "CWE-284",
				ModuleID:    "shadow",
			})
		}
	}

	return findings
}

func (m *ShadowModule) checkAgent(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	agentPaths := []string{
		"/agent", "/beacon", "/poll", "/checkin", "/callback",
		"/implant", "/bot", "/register", "/enroll", "/handshake",
		"/api/agent", "/api/beacon", "/api/checkin", "/api/poll",
		"/agent/checkin", "/agent/register", "/beacon/poll",
		"/payload/agent", "/stager/checkin", "/implant/callback",
	}

	agentPayloads := []struct {
		body string
		name string
	}{
		{body: `{"id":"test-agent-001","os":"linux","arch":"amd64","hostname":"test"}`, name: "Linux agent"},
		{body: `{"id":"test-agent-001","os":"windows","arch":"x64","hostname":"DESKTOP-TEST"}`, name: "Windows agent"},
		{body: `{"beacon_id":"test-001","ip":"127.0.0.1","user":"root"}`, name: "Beacon checkin"},
		{body: `{"callback":"test","type":"poll","uptime":3600}`, name: "Poll callback"},
	}

agentLoop:
	for _, path := range agentPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if resp.StatusCode == 200 {
			indicators := []string{"agent", "beacon", "implant", "callback", "checkin", "poll", "task", "command", "bot", "payload"}
			for _, ind := range indicators {
				if strings.Contains(respBody, ind) {
					findings = append(findings, &models.Finding{
						Title:       "Shadow - Malware Agent Endpoint",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Malware agent endpoint at %s (status: %d, matched: %s)", path, resp.StatusCode, ind),
						Description: fmt.Sprintf("Malware agent endpoint discovered at %s. Agents use this for checkin, polling, and receiving commands.", path),
						Remediation: "Block agent communication. Isolate infected hosts. Analyze agent behavior for IOCs.",
						CWEID:       "CWE-284",
						ModuleID:    "shadow",
					})
					continue agentLoop
				}
			}
		}

		for _, ap := range agentPayloads {
			resp, err := m.client.Post(fullURL, ap.body)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 202 {
				respBody := strings.ToLower(resp.Body)
				for _, ind := range []string{"ok", "ack", "received", "registered", "task", "wait", "poll", "beacon"} {
					if strings.Contains(respBody, ind) {
						findings = append(findings, &models.Finding{
							Title:       "Shadow - Agent Registration / Checkin",
							Severity:    models.Critical,
							Confidence:  models.HighConfidence,
							URL:         fullURL,
							Payload:     ap.name,
							Evidence:    fmt.Sprintf("Agent checkin accepted at %s (status: %d, payload: %s)", path, resp.StatusCode, ap.name),
							Description: fmt.Sprintf("Agent registration/checkin at %s accepted registration of %s.", path, ap.name),
							Remediation: "Block agent communication channels. Monitor for unauthorized device enrollment.",
							CWEID:       "CWE-284",
							ModuleID:    "shadow",
						})
						continue agentLoop
					}
				}
			}
		}
	}

	agentBeaconPaths := []string{"/beacon", "/poll", "/callback", "/checkin"}
	tmo := 8 * time.Second
	for _, path := range agentBeaconPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		start := time.Now()
		resp, err := m.client.Get(fullURL)
		elapsed := time.Since(start)
		if err == nil {
			_ = resp
			if elapsed > tmo/2 {
				findings = append(findings, &models.Finding{
					Title:       "Shadow - Long-Poll Beacon Endpoint",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Long-poll response time: %v at %s", elapsed, path),
					Description: fmt.Sprintf("Endpoint %s exhibits long-poll behavior typical of agent beaconing (response time: %v).", path, elapsed),
					Remediation: "Investigate suspicious long-poll endpoints. Block if confirmed C2 communication.",
					CWEID:       "CWE-284",
					ModuleID:    "shadow",
				})
			}
		}
	}

	return findings
}

func (m *ShadowModule) checkTunnel(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	tunnelTests := []struct {
		name       string
		path       string
		method     string
		body       string
		headers    map[string]string
		indicators []string
	}{
		{
			name:       "DNS Tunneling",
			path:       "/dns",
			method:     "GET",
			headers:    map[string]string{"Accept": "application/dns-message"},
			indicators: []string{"dns", "tunnel", "query"},
		},
		{
			name:       "ICMP Tunneling",
			path:       "/icmp",
			method:     "GET",
			indicators: []string{"icmp", "ping", "echo"},
		},
		{
			name:       "Domain Fronting",
			path:       "/cdn",
			method:     "GET",
			headers:    map[string]string{"Host": target.Domain},
			indicators: []string{"cdn", "cloudfront", "akamai", "cloudflare"},
		},
		{
			name:       "HTTP Tunnel",
			path:       "/tunnel",
			method:     "POST",
			body:       `{"target":"internal.service:8080","data":"test"}`,
			headers:    map[string]string{"Content-Type": "application/json"},
			indicators: []string{"tunnel", "proxy", "forward"},
		},
		{
			name:       "SSH Tunnel",
			path:       "/ssh",
			method:     "POST",
			body:       `{"host":"internal.db","port":3306}`,
			headers:    map[string]string{"Content-Type": "application/json"},
			indicators: []string{"ssh", "tunnel", "forward"},
		},
		{
			name:       "SOCKS Proxy",
			path:       "/socks",
			method:     "GET",
			indicators: []string{"socks", "proxy", "tunnel"},
		},
	}

	for _, tt := range tunnelTests {
		fullURL := strings.TrimRight(target.URL, "/") + tt.path

		var resp *fanghttp.Response
		var err error

		switch tt.method {
		case "POST":
			req := fanghttp.NewRequest("POST", fullURL)
			req.Body = tt.body
			for k, v := range tt.headers {
				req.Headers[k] = v
			}
			resp, err = m.client.Do(req)
		default:
			if len(tt.headers) > 0 {
				resp, err = m.client.DoRaw(tt.method, fullURL, tt.headers, "")
			} else {
				resp, err = m.client.Get(fullURL)
			}
		}

		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		matched := false
		for _, ind := range tt.indicators {
			if strings.Contains(respBody, ind) {
				matched = true
				break
			}
		}

		if matched || resp.StatusCode == 200 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Shadow - C2 Tunnel Detected (%s)", tt.name),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Tunnel endpoint at %s (status: %d, tunnel type: %s)", tt.path, resp.StatusCode, tt.name),
				Description: fmt.Sprintf("C2 tunnel detected at %s using %s. Enables covert communication and data exfiltration.", tt.path, tt.name),
				Remediation: "Block tunnel endpoints. Implement DPI for DNS/ICMP tunneling. Use domain fronting detection.",
				CWEID:       "CWE-284",
				ModuleID:    "shadow",
			})
		}
	}

	domainFrontingHeaders := []map[string]string{
		{"Host": "www.cloudflare.com", "X-Forwarded-Host": target.Domain},
		{"Host": "cdn.cloudfront.net", "X-Forwarded-For": target.Domain},
	}

	for _, dfHeaders := range domainFrontingHeaders {
		resp, err := m.client.DoRaw("GET", target.URL, dfHeaders, "")
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "cloudflare") || strings.Contains(respBody, "cloudfront") || strings.Contains(respBody, "akamai") {
			findings = append(findings, &models.Finding{
				Title:       "Shadow - Domain Fronting Possible",
				Severity:    models.High,
				Confidence:  models.LowConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Domain fronting test returned CDN content (status: %d)", resp.StatusCode),
				Description: "Target may be susceptible to domain fronting attacks for C2 communication concealment.",
				Remediation: "Use strict SNI matching. Disable wildcard certificate usage. Validate Host header against allowed domains.",
				CWEID:       "CWE-284",
				ModuleID:    "shadow",
			})
		}
	}

	return findings
}

func (m *ShadowModule) checkBeacon(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	beaconPaths := []string{
		"/beacon", "/poll", "/checkin", "/callback", "/sync",
		"/heartbeat", "/ping", "/alive", "/status", "/health",
		"/api/beacon", "/api/poll", "/api/heartbeat", "/api/ping",
	}

	beaconPatterns := []struct {
		name       string
		method     string
		body       string
		headers    map[string]string
		indicators []string
	}{
		{
			name:       "BeaconPoll",
			method:     "GET",
			indicators: []string{"beacon", "poll", "wait", "sleep", "jitter"},
		},
		{
			name:       "BeaconCheckin",
			method:     "POST",
			body:       `{"id":"beacon-test","uptime":3600,"ip":"1.2.3.4"}`,
			headers:    map[string]string{"Content-Type": "application/json"},
			indicators: []string{"ok", "ack", "task", "wait"},
		},
		{
			name:       "BeaconHeartbeat",
			method:     "GET",
			indicators: []string{"heartbeat", "alive", "pong"},
		},
		{
			name:       "BeaconTasking",
			method:     "POST",
			body:       `{"id":"beacon-test","action":"get_tasks"}`,
			headers:    map[string]string{"Content-Type": "application/json"},
			indicators: []string{"task", "command", "script", "shell"},
		},
	}

beaconLoop:
	for _, path := range beaconPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		for _, bp := range beaconPatterns {
			var resp *fanghttp.Response
			var err error

			switch bp.method {
			case "POST":
				req := fanghttp.NewRequest("POST", fullURL)
				req.Body = bp.body
				for k, v := range bp.headers {
					req.Headers[k] = v
				}
				resp, err = m.client.Do(req)
			default:
				resp, err = m.client.Get(fullURL)
			}

			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, ind := range bp.indicators {
				if strings.Contains(respBody, ind) || strings.Contains(strings.ToLower(resp.Status), ind) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("Shadow - Beacon Pattern Detected (%s)", bp.name),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Beacon pattern at %s (status: %d, matched: %s)", path, resp.StatusCode, ind),
						Description: fmt.Sprintf("Beaconing pattern detected at %s using %s. Indicates active C2 communication.", path, bp.name),
						Remediation: "Block beacon communication. Isolate compromised hosts. Hunt for additional C2 infrastructure.",
						CWEID:       "CWE-284",
						ModuleID:    "shadow",
					})
					continue beaconLoop
				}
			}
		}

		start := time.Now()
		resp1, err1 := m.client.Get(fullURL)
		time.Sleep(200 * time.Millisecond)
		resp2, err2 := m.client.Get(fullURL)

		if err1 == nil && err2 == nil {
			_ = resp1
			_ = resp2
			duration1 := time.Since(start)
			_ = duration1

			respBody1 := strings.ToLower(resp1.Body)
			respBody2 := strings.ToLower(resp2.Body)
			if respBody1 == respBody2 && resp1.StatusCode == resp2.StatusCode && resp1.StatusCode == 200 {
				if len(respBody1) < 100 {
					findings = append(findings, &models.Finding{
						Title:       "Shadow - Beacon Response Pattern",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Static beacon response at %s (size: %d bytes, consistent across polls)", path, len(respBody1)),
						Description: fmt.Sprintf("Endpoint %s returns consistent responses, typical of beacon polling patterns used by C2 agents.", path),
						Remediation: "Investigate consistent polling endpoints. Implement behavioral detection for beacon patterns.",
						CWEID:       "CWE-284",
						ModuleID:    "shadow",
					})
				}
			}
		}
	}

	jitterPaths := []string{"/beacon", "/poll", "/checkin", "/callback"}
	for _, path := range jitterPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		var durations []time.Duration

		for i := 0; i < 3; i++ {
			start := time.Now()
			resp, err := m.client.Get(fullURL)
			if err != nil {
				break
			}
			_ = resp
			durations = append(durations, time.Since(start))
		}

		if len(durations) == 3 {
			avg := (durations[0] + durations[1] + durations[2]) / 3
			for _, d := range durations {
				diff := d - avg
				if diff < 0 {
					diff = -diff
				}
				if diff > avg/2 {
					findings = append(findings, &models.Finding{
						Title:       "Shadow - Beacon Jitter Detected",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Response time jitter detected at %s (times: %v, %v, %v)", path, durations[0], durations[1], durations[2]),
						Description: fmt.Sprintf("Endpoint %s exhibits response time jitter, indicative of beacon randomization (jitter) used by C2 frameworks.", path),
						Remediation: "Implement temporal analysis detection for jitter patterns. Use ML-based beacon detection.",
						CWEID:       "CWE-284",
						ModuleID:    "shadow",
					})
					break
				}
			}
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&ShadowModule{})
}
