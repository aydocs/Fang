package rfid

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type RfidModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *RfidModule) ID() string   { return "rfid" }
func (m *RfidModule) Name() string { return "RFID & NFC Exposure" }
func (m *RfidModule) Description() string {
	return "Detects exposed RFID/NFC endpoints, reader web panels, exposed tag data, and card cloning interfaces"
}
func (m *RfidModule) Severity() models.Severity { return models.High }

func (m *RfidModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *RfidModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkRfidEndpoints(ctx, target)...)
	findings = append(findings, m.checkReaderPanels(ctx, target)...)
	findings = append(findings, m.checkTagData(ctx, target)...)
	findings = append(findings, m.checkCloneEndpoints(ctx, target)...)

	return findings, nil
}

func (m *RfidModule) checkRfidEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/rfid", "/nfc", "/tag", "/tags",
		"/api/rfid", "/api/nfc", "/api/tag",
		"/rfid/read", "/nfc/read", "/tag/read",
		"/rfid/status", "/nfc/status",
		"/rfid/tags", "/nfc/tags",
		"/rfid/info", "/nfc/info",
	}
	rfidIndicators := []string{"rfid", "nfc", "tag", "uid", "mifare", "felica", "iso14443", "iso15693", "ntag", "card", "reader", "proximity"}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			matchedCount := 0
			for _, ind := range rfidIndicators {
				if strings.Contains(body, ind) {
					matchedCount++
				}
			}
			if matchedCount >= 2 {
				findings = append(findings, &models.Finding{
					Title:       "RFID / NFC Endpoint Exposed",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("RFID/NFC endpoint accessible at %s (matched %d indicators)", path, matchedCount),
					Description: fmt.Sprintf("An RFID or NFC endpoint is exposed at %s. This may allow attackers to interact with RFID readers, enumerate tags, and access access control systems.", path),
					Remediation: "Restrict access to RFID/NFC endpoints. Use authentication for tag reading/writing. Implement encryption for RFID communication. Audit all RFID system access.",
					CWEID:       "CWE-200",
					ModuleID:    "rfid",
				})
			}
		}
	}
	return findings
}

func (m *RfidModule) checkReaderPanels(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/reader", "/readers", "/tag-reader", "/tagreader",
		"/rfid/reader", "/nfc/reader", "/card-reader",
		"/api/reader", "/api/readers", "/rfid-reader",
		"/readers/status", "/reader/config",
		"/rfid/panel", "/nfc/panel",
		"/access/reader", "/door/reader",
	}
	panelIndicators := []string{"reader", "rfid", "nfc", "card", "access", "door", "gate", "controller", "firmware", "serial", "model", "status", "connected", "antenna"}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			matchedCount := 0
			for _, ind := range panelIndicators {
				if strings.Contains(body, ind) {
					matchedCount++
				}
			}
			if matchedCount >= 3 {
				findings = append(findings, &models.Finding{
					Title:       "RFID Reader Web Panel Exposed",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("RFID reader management panel at %s (matched %d panel indicators)", path, matchedCount),
					Description: fmt.Sprintf("An RFID reader management web panel is exposed at %s. This provides control over physical access readers, including door locks, gate controls, and tag enrollment.", path),
					Remediation: "Disable remote access to RFID reader panels. Use network segmentation. Implement strong authentication. Change all default passwords on reader hardware.",
					CWEID:       "CWE-200",
					ModuleID:    "rfid",
				})
			}
		}
	}
	return findings
}

func (m *RfidModule) checkTagData(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/rfid/tags", "/nfc/tags", "/api/tags",
		"/rfid/tag-data", "/tags/list",
		"/api/rfid/tags", "/api/nfc/cards",
		"/rfid/dump", "/nfc/dump",
		"/cards", "/access/cards", "/badges",
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
			tagIndicators := []string{"uid", "tagid", "cardid", "mifare", "tag_data", "sector", "block", "key", "auth", "access_bits"}
			matchedCount := 0
			for _, ind := range tagIndicators {
				if strings.Contains(body, ind) {
					matchedCount++
				}
			}
			if matchedCount >= 2 || (isJSON && (strings.Contains(body, "\"uid\"") || strings.Contains(body, "\"card_id\""))) {
				findings = append(findings, &models.Finding{
					Title:       "RFID Tag Data Exposed",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("RFID tag data accessible at %s (matched %d tag indicators)", path, matchedCount),
					Description: fmt.Sprintf("RFID tag data is exposed at %s. This reveals tag UIDs, sector data, access keys, and cardholder information. Attackers can clone tags and bypass physical access controls.", path),
					Remediation: "Do not expose RFID tag data via web interfaces. Encrypt tag data at rest. Implement mutual authentication between tags and readers. Audit all access to tag databases.",
					CWEID:       "CWE-200",
					ModuleID:    "rfid",
				})
			}
		}
	}
	return findings
}

func (m *RfidModule) checkCloneEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/rfid/clone", "/nfc/clone", "/api/clone",
		"/rfid/write", "/nfc/write", "/api/rfid/write",
		"/rfid/program", "/nfc/program",
		"/tag/clone", "/tag/write", "/tag/program",
		"/mifare/clone", "/mifare/write",
		"/rfid/emulate", "/nfc/emulate",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "clone") || strings.Contains(body, "write") || strings.Contains(body, "program") || strings.Contains(body, "emulate") || strings.Contains(body, "mifare") || strings.Contains(body, "magic") || strings.Contains(body, "uid") || strings.Contains(body, "sector") {
				findings = append(findings, &models.Finding{
					Title:       "RFID / NFC Cloning Endpoint Detected",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("RFID tag cloning/writing endpoint accessible at %s", path),
					Description: fmt.Sprintf("An RFID or NFC tag cloning endpoint is exposed at %s. This allows attackers to clone access cards, badge credentials, and RFID tags, enabling physical security bypass.", path),
					Remediation: "Remove or disable RFID cloning/writing interfaces immediately. Implement tag authentication (e.g., Mifare DESFire, EV2). Use cryptographic authentication for all RFID systems. Audit physical security systems.",
					CWEID:       "CWE-200",
					ModuleID:    "rfid",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&RfidModule{})
}
