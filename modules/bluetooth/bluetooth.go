package bluetooth

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type BluetoothModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *BluetoothModule) ID() string   { return "bluetooth" }
func (m *BluetoothModule) Name() string { return "Bluetooth Security Assessment" }
func (m *BluetoothModule) Description() string {
	return "Detects Bluetooth service exposure, BLE beacon config leaks, pairing data leaks, and beacon configuration exposure"
}
func (m *BluetoothModule) Severity() models.Severity { return models.Critical }

func (m *BluetoothModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *BluetoothModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkBluetoothEndpoints(ctx, target)...)
	findings = append(findings, m.checkBLEBeaconConfig(ctx, target)...)
	findings = append(findings, m.checkPairingData(ctx, target)...)
	findings = append(findings, m.checkBeaconConfigExposure(ctx, target)...)

	return findings, nil
}

var bluetoothEndpoints = []string{
	"/bluetooth", "/api/bt", "/ble", "/api/ble",
	"/bluetooth/status", "/api/bluetooth",
	"/bt", "/api/v1/ble", "/api/v1/bluetooth",
	"/bluetooth/config", "/ble/config",
	"/api/ble/status", "/api/bt/status",
	"/bluetooth/scan", "/ble/scan",
	"/api/ble/scan", "/api/bt/scan",
	"/system/bluetooth", "/config/bluetooth",
	"/rest/bluetooth", "/api/bluetooth/status",
}

func (m *BluetoothModule) checkBluetoothEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range bluetoothEndpoints {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		btIndicators := []string{"bluetooth", "ble", "bluetooth low energy",
			"beacon", "device", "peripheral", "central",
			"scanning", "discovery", "advertisement",
			"service", "characteristic", "uuid"}

		matched := 0
		for _, ind := range btIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 2 {
			findings = append(findings, &models.Finding{
				Title:       "Bluetooth Service Endpoint Exposed",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Bluetooth/BLE endpoint accessible, %d indicators matched", matched),
				Description: fmt.Sprintf("Bluetooth service endpoint %s is exposed via HTTP. This may allow remote Bluetooth management and device discovery.", path),
				Remediation: "Restrict access to Bluetooth management endpoints. Implement authentication and disable remote Bluetooth management if not required.",
				CWEID:       "CWE-200",
				ModuleID:    "bluetooth",
			})
		}
	}

	return findings
}

var bleBeaconPaths = []string{
	"/beacon", "/beacons", "/api/beacon", "/api/beacons",
	"/ble/beacon", "/ble/beacons", "/api/ble/beacon",
	"/config/beacon", "/config/ble",
	"/eddystone", "/ibeacon", "/api/eddystone", "/api/ibeacon",
	"/beacon/config", "/ble/beacon/config",
}

func (m *BluetoothModule) checkBLEBeaconConfig(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range bleBeaconPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		beaconIndicators := []string{"uuid", "major", "minor", "identifier",
			"namespace", "instance", "txpower", "tx_power",
			"measured_power", "advertising", "interval",
			"beacon", "eddystone", "ibeacon"}

		matched := 0
		var matchedKeywords []string
		for _, ind := range beaconIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
				matchedKeywords = append(matchedKeywords, ind)
			}
		}

		if matched >= 3 {
			findings = append(findings, &models.Finding{
				Title:       "BLE Beacon Configuration Leaked",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Beacon config parameters exposed: %s", strings.Join(matchedKeywords, ", ")),
				Description: fmt.Sprintf("BLE beacon configuration is exposed at %s. Beacon parameters (UUID, major, minor) can be used to track or spoof beacons.", path),
				Remediation: "Secure beacon configuration endpoints. Change default beacon UUIDs and restrict access to configuration interfaces.",
				CWEID:       "CWE-200",
				ModuleID:    "bluetooth",
			})
		}
	}

	return findings
}

var pairingDataPatterns = []string{
	"pairing", "paired", "bond", "bonding",
	"pairing_key", "link_key", "ltk", "long_term_key",
	"irk", "identity_resolving", "csrk", "connection_signature",
	"pin_code", "passkey", "bt_pin", "bluetooth_pin",
	"pairing_data", "bluetooth_key",
}

func (m *BluetoothModule) checkPairingData(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	bodyLower := strings.ToLower(resp.Body)

	matched := 0
	var matchedPatterns []string
	for _, pat := range pairingDataPatterns {
		if strings.Contains(bodyLower, pat) {
			matched++
			matchedPatterns = append(matchedPatterns, pat)
		}
	}

	if matched >= 2 {
		findings = append(findings, &models.Finding{
			Title:       "Bluetooth Pairing Data Exposed",
			Severity:    models.Critical,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Pairing-related data found: %s", strings.Join(matchedPatterns, ", ")),
			Description: "Bluetooth pairing keys or bonding data exposed in page content. This could allow unauthorized device pairing and man-in-the-middle attacks.",
			Remediation: "Remove Bluetooth pairing data from accessible pages. Store keys in secure hardware-backed storage.",
			CWEID:       "CWE-200",
			ModuleID:    "bluetooth",
		})
	}

	if target.CrawlResult != nil {
		for _, scriptURL := range target.CrawlResult.Scripts {
			scriptResp, err := m.client.Get(scriptURL)
			if err != nil {
				continue
			}

			scriptBody := strings.ToLower(scriptResp.Body)
			matched = 0
			for _, pat := range pairingDataPatterns {
				if strings.Contains(scriptBody, pat) {
					matched++
				}
			}

			if matched >= 2 {
				findings = append(findings, &models.Finding{
					Title:       "Bluetooth Pairing Data in JavaScript",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         scriptURL,
					Evidence:    "Bluetooth pairing keys found in JavaScript source",
					Description: "Bluetooth pairing credentials exposed in JavaScript files. Can be extracted by any website visitor.",
					Remediation: "Remove Bluetooth pairing keys from client-side code. Use secure server-side Bluetooth management.",
					CWEID:       "CWE-200",
					ModuleID:    "bluetooth",
				})
			}
		}
	}

	return findings
}

func (m *BluetoothModule) checkBeaconConfigExposure(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	bodyLower := strings.ToLower(resp.Body)
	beaconTypes := []string{"eddystone", "ibeacon", "altbeacon"}

	for _, bt := range beaconTypes {
		if strings.Contains(bodyLower, bt) {
			beaconConfigValues := []string{"namespace", "instance", "url", "txpower",
				"interval", "measured power", "calibration"}

			configMatched := 0
			for _, val := range beaconConfigValues {
				if strings.Contains(bodyLower, val) {
					configMatched++
				}
			}

			if configMatched >= 2 {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("%s Beacon Configuration Exposure", bt),
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("%s beacon configuration parameters found in page content", bt),
					Description: fmt.Sprintf("%s beacon configuration data exposed on the page. Beacon settings can be used to track devices or spoof beacon presence.", bt),
					Remediation: "Remove beacon configuration data from web-accessible content. Restrict beacon management interfaces.",
					CWEID:       "CWE-200",
					ModuleID:    "bluetooth",
				})
			}
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&BluetoothModule{})
}
