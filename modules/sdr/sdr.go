package sdr

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SdrModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SdrModule) ID() string   { return "sdr" }
func (m *SdrModule) Name() string { return "SDR & Radio Frequency Exposure" }
func (m *SdrModule) Description() string {
	return "Detects exposed SDR (Software Defined Radio) endpoints, ADS-B receivers, GPS spoofing vectors, and radio configuration leaks"
}
func (m *SdrModule) Severity() models.Severity { return models.Medium }

func (m *SdrModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SdrModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkRadioEndpoints(ctx, target)...)
	findings = append(findings, m.checkADSB(ctx, target)...)
	findings = append(findings, m.checkGPS(ctx, target)...)
	findings = append(findings, m.checkRadioConfig(ctx, target)...)

	return findings, nil
}

func (m *SdrModule) checkRadioEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/sdr", "/radio", "/gnuradio", "/usrp",
		"/hackrf", "/rtl-sdr", "/rtlsdr",
		"/sdr/status", "/radio/status",
		"/api/sdr", "/api/radio", "/iq", "/waterfall",
		"/fft", "/spectrum", "/sdr/waterfall",
	}
	sdrIndicators := []string{"sdr", "software defined radio", "gnuradio", "usrp", "hackrf", "rtl-sdr", "rtlsdr", "center_freq", "sample_rate", "iq", "waterfall", "fft", "spectrum", "gain", "lna"}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			matchedCount := 0
			for _, ind := range sdrIndicators {
				if strings.Contains(body, ind) {
					matchedCount++
				}
			}
			if matchedCount >= 2 || strings.Contains(body, "center_freq") || strings.Contains(body, "sample_rate") {
				findings = append(findings, &models.Finding{
					Title:       "SDR / Radio Endpoint Exposed",
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("SDR radio endpoint accessible at %s (matched %d SDR indicators)", path, matchedCount),
					Description: fmt.Sprintf("A Software Defined Radio endpoint is exposed at %s. SDR servers allow remote radio frequency monitoring and transmission, potentially enabling signal interception and RF attacks.", path),
					Remediation: "Restrict access to SDR web interfaces. Use authentication. Disable transmit if not required. Monitor for unauthorized SDR access.",
					CWEID:       "CWE-200",
					ModuleID:    "sdr",
				})
			}
		}
	}
	return findings
}

func (m *SdrModule) checkADSB(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/adsb", "/dump1090", "/ads-b", "/adsb/exchange",
		"/dump1090/data.json", "/dump1090/data/aircraft.json",
		"/skyaware", "/tar1090", "/adsb/status",
		"/api/adsb", "/data/aircraft.json",
		"/radar", "/flight", "/traffic",
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
			isJSON := strings.Contains(contentType, "json")
			if strings.Contains(body, "hex") || strings.Contains(body, "flight") || strings.Contains(body, "altitude") || strings.Contains(body, "speed") || strings.Contains(body, "track") || strings.Contains(body, "lat") && strings.Contains(body, "lon") || strings.Contains(body, "squawk") || strings.Contains(body, "adsb") || strings.Contains(body, "dump1090") || strings.Contains(body, "aircraft") {
				finding := &models.Finding{
					Title:       "ADS-B / Dump1090 Endpoint Exposed",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("ADS-B receiver endpoint accessible at %s (JSON: %v)", path, isJSON),
					Description: fmt.Sprintf("An ADS-B (Automatic Dependent Surveillance-Broadcast) receiver endpoint is exposed at %s. This reveals real-time aircraft positions, flight numbers, altitudes, and speeds.", path),
					Remediation: "Restrict access to ADS-B web interfaces. Use authentication. Be aware that ADS-B data is broadcast unencrypted by aircraft and this is primarily an OPSEC concern.",
					CWEID:       "CWE-200",
					ModuleID:    "sdr",
				}
				if isJSON && strings.Contains(body, "hex") && strings.Contains(body, "lat") {
					finding.Title = "ADS-B Aircraft Data JSON Endpoint Exposed"
					finding.Evidence = fmt.Sprintf("ADS-B JSON aircraft data accessible at %s containing real-time flight telemetry", path)
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func (m *SdrModule) checkGPS(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/gps", "/location", "/api/gps", "/api/location",
		"/gps/data", "/gps/coordinates", "/geolocation",
		"/position", "/api/position", "/coordinates",
		"/gps/status", "/fix", "/satellites",
	}
	gpsIndicators := []string{"latitude", "longitude", "lat", "lon", "altitude", "gps", "coordinates", "position", "satellite", "fix", "hdop", "vdop", "pdop", "speed_over_ground", "true_course"}
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
			isJSON := strings.Contains(contentType, "json")
			matchedCount := 0
			for _, ind := range gpsIndicators {
				if strings.Contains(body, ind) {
					matchedCount++
				}
			}
			if matchedCount >= 2 || (isJSON && (strings.Contains(body, "\"lat\"") || strings.Contains(body, "\"latitude\""))) {
				findings = append(findings, &models.Finding{
					Title:       "GPS / Location Endpoint Exposed",
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("GPS/location endpoint accessible at %s (matched %d GPS indicators)", path, matchedCount),
					Description: fmt.Sprintf("A GPS or location endpoint is exposed at %s. This may reveal real-time geolocation data, satellite tracking information, or allow GPS coordinate spoofing.", path),
					Remediation: "Restrict access to GPS/location APIs. Authenticate all location requests. Validate GPS coordinates server-side to prevent spoofing. Use encrypted channels for location data.",
					CWEID:       "CWE-200",
					ModuleID:    "sdr",
				})
			}
		}
	}
	return findings
}

func (m *SdrModule) checkRadioConfig(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/sdr/config", "/radio/config", "/api/sdr/config",
		"/sdr/settings", "/gnuradio/config",
		"/config/sdr", "/api/radio/settings",
		"/sdr/status.json", "/radio/info",
	}
	configIndicators := []string{
		"center_freq", "sample_rate", "rf_gain", "lna_gain",
		"bandwidth", "frequency", "freq_correction", "ppm",
		"antenna", "decimation", "filter", "tuner",
		"if_gain", "bb_gain", "mixer_gain",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			var matched []string
			for _, ind := range configIndicators {
				if strings.Contains(body, ind) {
					matched = append(matched, ind)
				}
			}
			if len(matched) > 0 {
				findings = append(findings, &models.Finding{
					Title:       "SDR Radio Configuration Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("SDR radio configuration exposed at %s - contains: %s", path, strings.Join(matched, ", ")),
					Description: fmt.Sprintf("Software Defined Radio configuration data is exposed at %s revealing center frequency, sample rate, gain settings, and tuner parameters. This information can be used to target specific RF communications.", path),
					Remediation: "Require authentication for SDR configuration endpoints. Do not expose radio tuning parameters publicly. Use API keys for SDR control interfaces.",
					CWEID:       "CWE-200",
					ModuleID:    "sdr",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&SdrModule{})
}
