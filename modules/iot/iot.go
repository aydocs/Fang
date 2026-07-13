package iot

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

type IotModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *IotModule) ID() string   { return "iot" }
func (m *IotModule) Name() string { return "IoT & Embedded Device Security" }
func (m *IotModule) Description() string {
	return "Detects exposed IoT protocols, MQTT/CoAP endpoints, admin panels, camera streams, and firmware update vectors"
}
func (m *IotModule) Severity() models.Severity { return models.High }

func (m *IotModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *IotModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkMQTT(ctx, target)...)
	findings = append(findings, m.checkCoAP(ctx, target)...)
	findings = append(findings, m.checkAdminPanels(ctx, target)...)
	findings = append(findings, m.checkCameraStreams(ctx, target)...)
	findings = append(findings, m.checkFirmware(ctx, target)...)

	return findings, nil
}

func (m *IotModule) checkMQTT(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/mqtt", "/api/mqtt", "/mqtt/", "/ws/mqtt",
		"/.well-known/mqtt", "/mqtt/status",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "mqtt") || strings.Contains(body, "mosquitto") || strings.Contains(body, "eclipse") || strings.Contains(body, "paho") || strings.Contains(body, "mqtt") {
				findings = append(findings, &models.Finding{
					Title:       "MQTT Endpoint Exposed via HTTP",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("MQTT broker endpoint accessible at %s", path),
					Description: "An MQTT broker endpoint is exposed via HTTP. MQTT is a lightweight IoT messaging protocol and unauthenticated access allows attackers to publish/subscribe to all topics, control IoT devices, and intercept sensor data.",
					Remediation: "Require MQTT authentication. Use TLS for MQTT connections. Restrict topic access with ACLs. Disable HTTP-to-MQTT bridges if not required.",
					CWEID:       "CWE-306",
					ModuleID:    "iot",
				})
			}
		}
	}
	mqttPorts := []string{"1883", "8883", "8083", "8081"}
	for _, port := range mqttPorts {
		addr := target.Domain + ":" + port
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		findings = append(findings, &models.Finding{
			Title:       "MQTT Port Open",
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         fmt.Sprintf("tcp://%s", addr),
			Evidence:    fmt.Sprintf("MQTT port %s is open on %s", port, target.Domain),
			Description: fmt.Sprintf("Port %s (MQTT) is open. MQTT is commonly used in IoT deployments and if unauthenticated, allows full access to the message bus.", port),
			Remediation: "Close unused MQTT ports. Use TLS (8883) instead of plain TCP (1883). Implement client authentication.",
			CWEID:       "CWE-306",
			ModuleID:    "iot",
		})
	}
	return findings
}

func (m *IotModule) checkCoAP(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/coap", "/.well-known/core", "/.well-known/coap",
		"/api/coap", "/coap/", "/core",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "</") || strings.Contains(body, "rt=") || strings.Contains(body, "if=") || strings.Contains(body, "ct=") || strings.Contains(body, "coap") || strings.Contains(body, "core") {
				findings = append(findings, &models.Finding{
					Title:       "CoAP Endpoint Exposed via HTTP",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("CoAP/well-known endpoint accessible at %s", path),
					Description: "A Constrained Application Protocol (CoAP) endpoint is exposed. CoAP is used in IoT devices and may expose resource discovery information, allowing attackers to enumerate device capabilities.",
					Remediation: "Disable CoAP-to-HTTP bridges. Restrict CoAP access to local network. Implement DTLS for CoAP security.",
					CWEID:       "CWE-200",
					ModuleID:    "iot",
				})
			}
		}
	}
	return findings
}

func (m *IotModule) checkAdminPanels(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/admin", "/config", "/settings", "/management",
		"/device", "/devices", "/setup", "/wizard",
		"/status", "/diagnostics", "/debug", "/api/admin",
	}
	iotPorts := []string{"80", "8080", "443", "8443", "9090", "9000"}
	adminIndicators := []string{"admin", "password", "login", "username", "device", "router", "camera", "sensor", "gateway", "firmware", "config"}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			matchedCount := 0
			for _, ind := range adminIndicators {
				if strings.Contains(body, ind) {
					matchedCount++
				}
			}
			if matchedCount >= 3 {
				findings = append(findings, &models.Finding{
					Title:       "IoT Device Admin Panel Detected",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Potential IoT admin panel at %s (matched %d indicators)", path, matchedCount),
					Description: fmt.Sprintf("An IoT device administration panel may be exposed at %s. IoT admin panels often have default credentials and lack proper security controls.", path),
					Remediation: "Change default credentials. Disable remote admin access. Use VPN for device management. Implement rate limiting and account lockout.",
					CWEID:       "CWE-306",
					ModuleID:    "iot",
				})
			}
		}
	}
	for _, port := range iotPorts {
		addr := target.Domain + ":" + port
		u := fmt.Sprintf("http://%s/admin", addr)
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "admin") || strings.Contains(body, "login") || strings.Contains(body, "password") || strings.Contains(body, "dashboard") {
				findings = append(findings, &models.Finding{
					Title:       "IoT Device Admin Panel on Custom Port",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Admin panel accessible on port %s at /admin", port),
					Description: fmt.Sprintf("An IoT admin panel is accessible on port %s. IoT devices often run embedded web servers with minimal security.", port),
					Remediation: "Disable remote administration. Use strong authentication. Implement HTTPS. Restrict access by IP.",
					CWEID:       "CWE-306",
					ModuleID:    "iot",
				})
			}
		}
	}
	return findings
}

func (m *IotModule) checkCameraStreams(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/stream", "/video", "/mjpeg", "/mjpegstream",
		"/cam", "/camera", "/live", "/liveview",
		"/snapshot", "/image", "/capture", "/axis-cgi/mjpg/video.cgi",
		"/cgi-bin/", "/h264stream", "/video_feed",
		"/api/stream", "/api/camera", "/record",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			contentType := ""
			if resp.Headers != nil {
				contentType = strings.ToLower(resp.Headers.Get("Content-Type"))
			}
			if strings.Contains(contentType, "multipart/x-mixed-replace") || strings.Contains(contentType, "video/") || strings.Contains(contentType, "image/jpeg") || strings.Contains(contentType, "image/jpg") || strings.Contains(body, "mjpeg") || strings.Contains(body, "video") || strings.Contains(body, "liveview") || strings.Contains(body, "camera") || strings.Contains(body, "stream") {
				findings = append(findings, &models.Finding{
					Title:       "Exposed Camera Video Stream",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Camera video stream accessible at %s (Content-Type: %s)", path, contentType),
					Description: fmt.Sprintf("A live camera video stream is exposed at %s. Unauthenticated access allows attackers to view live footage, which is a severe privacy and security violation.", path),
					Remediation: "Require authentication for all camera streams. Use RTSP with authentication instead of HTTP. Disable unused camera interfaces. Change default camera passwords.",
					CWEID:       "CWE-306",
					ModuleID:    "iot",
				})
			}
		}
	}
	return findings
}

func (m *IotModule) checkFirmware(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/firmware", "/firmware/", "/firmware.bin",
		"/update", "/ota", "/ota_update",
		"/upgrade", "/download/firmware", "/api/firmware",
		"/firmware-update", "/fw", "/latest-firmware",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			contentType := ""
			if resp.Headers != nil {
				contentType = strings.ToLower(resp.Headers.Get("Content-Type"))
			}
			if strings.Contains(contentType, "octet-stream") || strings.Contains(contentType, "binary") || strings.Contains(body, "firmware") || strings.Contains(body, "ota") || strings.Contains(body, "upgrade") || strings.Contains(body, "version") || strings.Contains(body, "release") || strings.Contains(body, "update") || strings.Contains(body, "checksum") || strings.Contains(body, "md5") || strings.Contains(body, "sha256") {
				findings = append(findings, &models.Finding{
					Title:       "Firmware Update Endpoint Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Firmware/OTA endpoint accessible at %s (Content-Type: %s)", path, contentType),
					Description: fmt.Sprintf("A firmware update or OTA endpoint is exposed at %s. Attackers can extract firmware for vulnerability analysis or serve malicious firmware updates to devices.", path),
					Remediation: "Require authentication for firmware downloads. Sign firmware images cryptographically. Use HTTPS for OTA updates. Implement secure boot and firmware verification.",
					CWEID:       "CWE-306",
					ModuleID:    "iot",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&IotModule{})
}
