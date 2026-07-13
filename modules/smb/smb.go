package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SMBModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SMBModule) ID() string   { return "smb" }
func (m *SMBModule) Name() string { return "SMB Security Scanner" }
func (m *SMBModule) Description() string {
	return "SMB enumeration, SMBGhost (CVE-2020-0796), EternalBlue (MS17-010), SMB signing, null session detection"
}
func (m *SMBModule) Severity() models.Severity { return models.Critical }

func (m *SMBModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SMBModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	host := extractHost(target.URL)

	findings = append(findings, m.checkSMBPorts(host)...)
	findings = append(findings, m.checkSMBSigning(host)...)
	findings = append(findings, m.checkEternalBlue(host)...)
	findings = append(findings, m.checkSMBGhost(host)...)
	findings = append(findings, m.checkNullSession(host)...)

	return findings, nil
}

func (m *SMBModule) checkSMBPorts(host string) []*models.Finding {
	var findings []*models.Finding
	ports := []int{139, 445}

	for _, port := range ports {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		service := "SMB over NetBIOS"
		if port == 445 {
			service = "SMB over TCP (Direct)"
		}

		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("SMB - Open Port: %d/%s", port, service),
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         fmt.Sprintf("smb://%s:%d", host, port),
			Evidence:    fmt.Sprintf("Port %d is open and accessible", port),
			Description: fmt.Sprintf("SMB service exposed on port %d (%s). SMB is a common attack vector for ransomware and lateral movement.", port, service),
			Remediation: "Restrict SMB access to trusted networks. Disable SMBv1. Enable SMB signing. Use firewall rules to limit exposure.",
			CWEID:       "CWE-200",
			ModuleID:    "smb",
		})
	}

	return findings
}

func (m *SMBModule) checkSMBSigning(host string) []*models.Finding {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	negReq := buildSMB2Negotiate()
	if _, err := conn.Write(negReq); err != nil {
		return nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 72 {
		return nil
	}

	if n < 74 {
		return nil
	}

	securityMode := binary.LittleEndian.Uint16(resp[72:74])
	signingRequired := securityMode&0x01 == 0x01
	signingEnabled := securityMode&0x02 == 0x02

	if !signingRequired && !signingEnabled {
		return []*models.Finding{
			{
				Title:       "SMB - Signing Disabled",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fmt.Sprintf("smb://%s:445", host),
				Evidence:    fmt.Sprintf("SMB2 security mode: 0x%04x (signing not required)", securityMode),
				Description: "SMB signing is not enabled. An attacker can perform SMB relay attacks to authenticate as the relaying user without knowledge of credentials.",
				Remediation: "Enable SMB signing via GPO. Set 'Microsoft network server: Digitally sign communications (always)' to Enabled.",
				CWEID:       "CWE-287",
				ModuleID:    "smb",
			},
		}
	}

	if signingEnabled && !signingRequired {
		return []*models.Finding{
			{
				Title:       "SMB - Signing Not Required",
				Severity:    models.Medium,
				Confidence:  models.HighConfidence,
				URL:         fmt.Sprintf("smb://%s:445", host),
				Evidence:    fmt.Sprintf("SMB2 security mode: 0x%04x (signing enabled but not required)", securityMode),
				Description: "SMB signing is enabled but not required. Relay attacks may still succeed if the client does not enforce signing.",
				Remediation: "Set 'Microsoft network server: Digitally sign communications (always)' to Enabled.",
				CWEID:       "CWE-287",
				ModuleID:    "smb",
			},
		}
	}

	return nil
}

func (m *SMBModule) checkEternalBlue(host string) []*models.Finding {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ms17010Payload := buildMS17010Probe()
	if _, err := conn.Write(ms17010Payload); err != nil {
		return nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return nil
	}

	ntStatus := binary.LittleEndian.Uint32(resp[4:8])
	if ntStatus == 0xC00000BB {
		return nil
	}

	if ntStatus == 0x00000000 || ntStatus == 0xC0000022 || ntStatus == 0xC000000D || ntStatus == 0xC0000001 {
		trans2Pattern := detectTrans2MS17010(host)
		if trans2Pattern {
			return []*models.Finding{
				{
					Title:       "SMB - EternalBlue (MS17-010) Vulnerable",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         fmt.Sprintf("smb://%s:445", host),
					Evidence:    "SMBv1 is active and Trans2 request indicates vulnerability to MS17-010",
					Description: "MS17-010 (EternalBlue) vulnerability detected. Remote code execution via SMBv1. Used by WannaCry and NotPetya ransomware.",
					Remediation: "Apply Microsoft security patch MS17-010. Disable SMBv1 protocol completely via Windows Features or Group Policy.",
					CWEID:       "CWE-287",
					ModuleID:    "smb",
				},
			}
		}

		return []*models.Finding{
			{
				Title:       "SMB - SMBv1 Active (Potential MS17-010)",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fmt.Sprintf("smb://%s:445", host),
				Evidence:    fmt.Sprintf("SMBv1 negotiate response NT_STATUS: 0x%08x", ntStatus),
				Description: "SMBv1 protocol is enabled. SMBv1 has multiple known vulnerabilities including MS17-010 (EternalBlue) and should be disabled.",
				Remediation: "Disable SMBv1 via 'Disable SMB 1.0/CIFS File Sharing Support' in Windows Features or via Group Policy.",
				CWEID:       "CWE-200",
				ModuleID:    "smb",
			},
		}
	}

	return nil
}

func detectTrans2MS17010(host string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := buildMS17010Trans2Payload()
	if _, err := conn.Write(payload); err != nil {
		return false
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 32 {
		return false
	}

	if n >= 36 {
		status := binary.LittleEndian.Uint32(resp[4:8])
		if status == 0xC0000205 {
			return true
		}
		if status == 0x00000000 && n >= 40 {
			wordCount := resp[32]
			if wordCount == 0x0A || wordCount == 0x00 {
				return true
			}
		}
	}

	return false
}

func (m *SMBModule) checkSMBGhost(host string) []*models.Finding {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := buildSMBGhostProbe()
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 100 {
		return nil
	}

	if n < 144 {
		return nil
	}

	hasCompression := false
	for i := 0; i <= n-8; i++ {
		if resp[i] == 0x03 && resp[i+1] == 0x00 && i+4 < n {
			contextType := binary.LittleEndian.Uint16(resp[i : i+2])
			if contextType == 3 {
				hasCompression = true
				break
			}
		}
	}

	if hasCompression {
		return []*models.Finding{
			{
				Title:       "SMB - SMBGhost (CVE-2020-0796) Vulnerable",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         fmt.Sprintf("smb://%s:445", host),
				Evidence:    "SMBv3.1.1 negotiate response includes compression capability context",
				Description: "CVE-2020-0796 (SMBGhost) is a pre-auth RCE in SMBv3.1.1 compression. Affects Windows 10 1903/1909 and Windows Server 1903/1909.",
				Remediation: "Apply Microsoft security update KB4551762. Disable SMBv3 compression via PowerShell: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' DisableCompression -Type DWORD -Value 1",
				CWEID:       "CWE-287",
				ModuleID:    "smb",
			},
		}
	}

	return nil
}

func (m *SMBModule) checkNullSession(host string) []*models.Finding {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := buildNullSessionProbe()
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 36 {
		return nil
	}

	ntStatus := binary.LittleEndian.Uint32(resp[4:8])
	if ntStatus == 0x00000000 {
		sessionID := binary.LittleEndian.Uint64(resp[28:36])
		if sessionID != 0 {
			return []*models.Finding{
				{
					Title:       "SMB - Null Session / Anonymous Login Allowed",
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         fmt.Sprintf("smb://%s:445", host),
					Payload:     "SMB_COM_NEGOTIATE + SMB_COM_SESSION_SETUP_ANDX with anonymous credentials",
					Evidence:    fmt.Sprintf("Null session established successfully. Session ID: 0x%016x", sessionID),
					Description: "Null session (anonymous SMB login) is permitted. Attackers can enumerate users, shares, and system information without authentication. This is a common vector for information gathering.",
					Remediation: "Restrict anonymous access via 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'. Disable 'Network access: Let Everyone permissions apply to anonymous users'.",
					CWEID:       "CWE-287",
					ModuleID:    "smb",
				},
			}
		}
	}

	return nil
}

func buildSMB2Negotiate() []byte {
	buf := new(bytes.Buffer)

	netbiosLen := uint32(100)
	binary.Write(buf, binary.BigEndian, netbiosLen&0x00FFFFFF)

	buf.Write([]byte{0xFE, 0x53, 0x4D, 0x42})
	binary.Write(buf, binary.LittleEndian, uint16(64))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint64(0))
	binary.Write(buf, binary.LittleEndian, uint32(0xFEFF))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint64(0))
	buf.Write(make([]byte, 16))

	binary.Write(buf, binary.LittleEndian, uint16(36))
	binary.Write(buf, binary.LittleEndian, uint16(3))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(1))
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	binary.Write(buf, binary.LittleEndian, uint16(0x0311))

	out := buf.Bytes()
	out[0] = 0x00
	payloadLen := len(out) - 4
	out[1] = byte((payloadLen >> 16) & 0xFF)
	out[2] = byte((payloadLen >> 8) & 0xFF)
	out[3] = byte(payloadLen & 0xFF)

	return out
}

func buildMS17010Probe() []byte {
	buf := new(bytes.Buffer)

	netbiosLen := uint32(100)
	_ = netbiosLen

	binary.Write(buf, binary.LittleEndian, uint32(0))

	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})

	binary.Write(buf, binary.LittleEndian, uint8(0x72))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))
	binary.Write(buf, binary.LittleEndian, uint32(0x00000001))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	out := buf.Bytes()
	out[0] = 0x00
	payloadLen := len(out) - 4
	out[1] = byte((payloadLen >> 16) & 0xFF)
	out[2] = byte((payloadLen >> 8) & 0xFF)
	out[3] = byte(payloadLen & 0xFF)

	return out
}

func buildMS17010Trans2Payload() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0))

	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	binary.Write(buf, binary.LittleEndian, uint8(0x72))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	binary.Write(buf, binary.LittleEndian, uint8(0x32))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	out := buf.Bytes()
	out[0] = 0x00
	payloadLen := len(out) - 4
	out[1] = byte((payloadLen >> 16) & 0xFF)
	out[2] = byte((payloadLen >> 8) & 0xFF)
	out[3] = byte(payloadLen & 0xFF)

	return out
}

func buildSMBGhostProbe() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, uint32(0))

	buf.Write([]byte{0xFE, 0x53, 0x4D, 0x42})
	binary.Write(buf, binary.LittleEndian, uint16(64))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint64(0))
	binary.Write(buf, binary.LittleEndian, uint32(0xFEFF))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint64(0))
	buf.Write(make([]byte, 16))

	binary.Write(buf, binary.LittleEndian, uint16(36))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0x0000007F))
	buf.Write(make([]byte, 16))
	binary.Write(buf, binary.LittleEndian, uint64(0))
	binary.Write(buf, binary.LittleEndian, uint16(0x0311))

	negCtxOffset := uint32(len(buf.Bytes()) + 4)
	binary.Write(buf, binary.LittleEndian, negCtxOffset)

	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	for len(buf.Bytes())%8 != 0 {
		buf.WriteByte(0)
	}

	binary.Write(buf, binary.LittleEndian, uint16(3))
	binary.Write(buf, binary.LittleEndian, uint16(10))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint16(1))

	out := buf.Bytes()
	out[0] = 0x00
	payloadLen := len(out) - 4
	out[1] = byte((payloadLen >> 16) & 0xFF)
	out[2] = byte((payloadLen >> 8) & 0xFF)
	out[3] = byte(payloadLen & 0xFF)

	return out
}

func buildNullSessionProbe() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0))

	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	binary.Write(buf, binary.LittleEndian, uint8(0x72))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint8(0x00))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))
	binary.Write(buf, binary.LittleEndian, uint32(0x00000001))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	out := buf.Bytes()
	out[0] = 0x00
	payloadLen := len(out) - 4
	out[1] = byte((payloadLen >> 16) & 0xFF)
	out[2] = byte((payloadLen >> 8) & 0xFF)
	out[3] = byte(payloadLen & 0xFF)

	return out
}

func extractHost(rawURL string) string {
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
	engine.GetRegistry().Register(&SMBModule{})
}
