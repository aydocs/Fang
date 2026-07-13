package reverse

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ReverseModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ReverseModule) ID() string   { return "reverse" }
func (m *ReverseModule) Name() string { return "Reverse Engineering & Binary Analysis Module" }
func (m *ReverseModule) Description() string {
	return "Ghidra headless integration, packer detection, shellcode emulation, binary patch diffing, and binary vulnerability scanning"
}
func (m *ReverseModule) Severity() models.Severity { return models.Critical }

func (m *ReverseModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *ReverseModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkGhidraEndpoints(ctx, target)...)
	findings = append(findings, m.checkUnpackerEndpoints(ctx, target)...)
	findings = append(findings, m.checkShellcodeEndpoints(ctx, target)...)
	findings = append(findings, m.checkPatchDiffEndpoints(ctx, target)...)
	findings = append(findings, m.checkBinaryScannerEndpoints(ctx, target)...)

	return findings, nil
}

func (m *ReverseModule) checkGhidraEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	ghidraPaths := []string{
		"/ghidra", "/api/ghidra", "/ghidra-server",
		"/v1/ghidra", "/ghidra/api",
		"/binary", "/exported-binary", "/download-binary",
		"/analyze", "/api/analyze", "/decompile",
		"/api/decompile", "/v1/decompile",
	}
	for _, path := range ghidraPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		for _, check := range []string{"ghidra", "Ghidra", "decompile", "Decompiler", "sleigh",
			"pcode", "PCode", "function", "analyze", "binary", "exported"} {
			if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
				severity := models.High
				if strings.Contains(path, "export") || strings.Contains(path, "download") {
					severity = models.Critical
				}
				findings = append(findings, &models.Finding{
					Title:       "Reverse - Ghidra RE Server Endpoint",
					Severity:    severity,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Ghidra-like endpoint found at %s (matched: '%s', status: %d)", path, check, resp.StatusCode),
					Description: fmt.Sprintf("Potential Ghidra reverse engineering server endpoint exposed at %s. May provide binary analysis, decompilation, or exported binaries.", path),
					Remediation: "Restrict Ghidra server access to internal network. Authenticate all API endpoints. Do not expose binary analysis interfaces.",
					CWEID:       "CWE-200",
					ModuleID:    "reverse",
				})
				break
			}
		}

		if resp.StatusCode == 200 && len(resp.Body) > 1000 {
			if strings.Contains(resp.Body, "MZ") || strings.Contains(resp.Body, "\x7fELF") ||
				strings.Contains(resp.Body, "PE") || strings.Contains(resp.Body, "Mach-O") {
				findings = append(findings, &models.Finding{
					Title:       "Reverse - Binary Export Endpoint",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Binary file accessible at %s (size: %d bytes)", path, len(resp.Body)),
					Description: fmt.Sprintf("Binary export endpoint at %s allows downloading compiled binaries. Can be used for reverse engineering and vulnerability analysis of proprietary software.", path),
					Remediation: "Block binary download endpoints. Authenticate access. Implement DRM or obfuscation for distributed binaries.",
					CWEID:       "CWE-200",
					ModuleID:    "reverse",
				})
			}
		}
	}

	return findings
}

func (m *ReverseModule) checkUnpackerEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	packerSignatures := []struct {
		name string
		sigs []string
	}{
		{name: "UPX", sigs: []string{"UPX", "UPX!", "upx", "upx0", "upx1"}},
		{name: "ASPack", sigs: []string{"ASPack", "ASPack2", "aspack"}},
		{name: "Themida", sigs: []string{"Themida", "themida", "WinLicense", "Oreans"}},
		{name: "VMProtect", sigs: []string{"VMProtect", "vmprotect", "VProtect"}},
		{name: "Enigma Protector", sigs: []string{"Enigma", "enigma", "enigma prot"}},
		{name: "Armadillo", sigs: []string{"Armadillo", "armadillo", "ArmDot"}},
		{name: "ASProtect", sigs: []string{"ASProtect", "asprotect"}},
		{name: "Obsidium", sigs: []string{"Obsidium", "obsidium"}},
		{name: "EXECryptor", sigs: []string{"EXECryptor", "execryptor"}},
		{name: "MoleBox", sigs: []string{"MoleBox", "molebox"}},
		{name: "MPRESS", sigs: []string{"MPRESS", "mpress"}},
		{name: "NsPack", sigs: []string{"NsPack", "nspack"}},
		{name: "PECompact", sigs: []string{"PECompact", "pecompact"}},
		{name: "PESpin", sigs: []string{"PESpin", "pespin"}},
		{name: "RLPack", sigs: []string{"RLPack", "rlpack"}},
		{name: "SVKP", sigs: []string{"SVKP", "svkp"}},
		{name: "Telock", sigs: []string{"Telock", "tBlock", "tLock"}},
		{name: "WWPack32", sigs: []string{"WWPack32", "wwpack32"}},
		{name: "Yoda Protector", sigs: []string{"Yoda", "yoda", "y0da"}},
		{name: "zProtect", sigs: []string{"zProtect", "zprotect"}},
		{name: "eXPressor", sigs: []string{"eXPressor", "expressor"}},
		{name: "DotFix", sigs: []string{"DotFix", "dotfix"}},
		{name: "FSG", sigs: []string{"FSG", "fsg!"}},
		{name: "Kkrunchy", sigs: []string{"Kkrunchy", "kkrunchy"}},
		{name: "MEW", sigs: []string{"MEW", "mew!"}},
		{name: "Petite", sigs: []string{"Petite", "petite"}},
		{name: "Shrinker", sigs: []string{"Shrinker", "shrinker"}},
		{name: "Upack", sigs: []string{"Upack", "upack"}},
		{name: "Confuser", sigs: []string{"Confuser", "confuser", "ConfuserEx"}},
		{name: "SmartAssembly", sigs: []string{"SmartAssembly", "smartassembly"}},
		{name: "Obfuscar", sigs: []string{"Obfuscar", "obfuscar"}},
		{name: "Dotfuscator", sigs: []string{"Dotfuscator", "dotfuscator"}},
		{name: "Agile.NET", sigs: []string{"Agile.NET", "agile.net"}},
		{name: "Babel Obfuscator", sigs: []string{"Babel", "babel obfuscator"}},
		{name: "Skater.NET", sigs: []string{"Skater", "skater.net"}},
		{name: "Spices.Obfuscator", sigs: []string{"Spices", "spices obfuscator"}},
		{name: "Phoenix Protector", sigs: []string{"Phoenix", "phoenix prot"}},
		{name: "MPRESS2", sigs: []string{"MPRESS2", "mpress2"}},
		{name: "VBox", sigs: []string{"VBox", "vbox"}},
		{name: "Steam", sigs: []string{"Steam", "steam", "Steam2"}},
		{name: "SafeNet", sigs: []string{"SafeNet", "safenet"}},
		{name: "HASP", sigs: []string{"HASP", "hasp", "Sentinel"}},
		{name: "CodeMeter", sigs: []string{"CodeMeter", "codemeter"}},
		{name: "DNGuard", sigs: []string{"DNGuard", "dnguard"}},
		{name: "DeepSea", sigs: []string{"DeepSea", "deepsea"}},
		{name: "MaxToCode", sigs: []string{"MaxToCode", "maxtocode"}},
		{name: "PELock", sigs: []string{"PELock", "pelock"}},
		{name: "PCGuard", sigs: []string{"PCGuard", "pcguard"}},
		{name: "ProtectPlus", sigs: []string{"ProtectPlus", "protectplus"}},
		{name: "VCAS", sigs: []string{"VCAS", "vcas"}},
	}

	packerPaths := []string{
		"/api/unpack", "/unpack", "/packer-detect", "/api/packer",
		"/binary-scan", "/api/binary-scan", "/upload", "/api/upload",
	}
	for _, path := range packerPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"sample":"test","type":"pe32"}`)
		if err != nil {
			continue
		}

		for _, p := range packerSignatures {
			for _, sig := range p.sigs {
				if strings.Contains(resp.Body, sig) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("Reverse - Packer Detection: %s", p.name),
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         fullURL,
						Payload:     `{"sample":"test","type":"pe32"}`,
						Evidence:    fmt.Sprintf("Packer signature '%s' for %s detected in response", sig, p.name),
						Description: fmt.Sprintf("%s packer detection available at %s. Packed binaries hinder analysis and may indicate malware.", p.name, path),
						Remediation: "Restrict binary analysis endpoints. Use packer detection in malware analysis pipelines. Unpack before distribution.",
						CWEID:       "CWE-200",
						ModuleID:    "reverse",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *ReverseModule) checkShellcodeEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	shellcodePaths := []string{
		"/shellcode", "/api/shellcode", "/asm", "/api/asm",
		"/sc", "/api/sc", "/emu", "/emulate", "/api/emulate",
		"/run-shellcode", "/api/exec", "/sandbox",
		"/api/sandbox", "/analysis", "/api/analysis",
	}
	for _, path := range shellcodePaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"shellcode":"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80","arch":"x86"}`)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		shellcodeIndicators := []string{"shellcode", "assembly", "opcode", "disasm",
			"emulate", "emu", "instruction", "executed", "register",
			"rax", "rbx", "rcx", "rdx", "eip", "esp", "ebp",
			"nop", "int 0x80", "syscall", "execve", "push", "pop",
		}
		for _, check := range shellcodeIndicators {
			if strings.Contains(bodyLower, check) {
				findings = append(findings, &models.Finding{
					Title:       "Reverse - Shellcode Analysis Endpoint",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Payload:     "shellcode payload test",
					Evidence:    fmt.Sprintf("Shellcode analysis endpoint responds (matched: '%s', status: %d)", check, resp.StatusCode),
					Description: fmt.Sprintf("Shellcode analysis/emulation endpoint at %s. Allows arbitrary shellcode execution analysis, potentially bypassing EDR/AV.", path),
					Remediation: "Restrict shellcode analysis endpoints. Implement sandboxing with network isolation. Log all analysis requests.",
					CWEID:       "CWE-200",
					ModuleID:    "reverse",
				})
				break
			}
		}
	}

	return findings
}

func (m *ReverseModule) checkPatchDiffEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	patchPaths := []string{
		"/patch", "/diff", "/binary-diff", "/api/diff",
		"/patch-tuesday", "/0day", "/vuln-diff",
		"/api/patch", "/bindiff", "/binary-diffing",
		"/bindiff", "/api/bindiff",
	}
	for _, path := range patchPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"original":"binary_a.bin","patched":"binary_b.bin","type":"pe32"}`)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		patchIndicators := []string{"diff", "patch", "bindiff", "different", "changed",
			"similarity", "function", "match", "compare",
			"block", "graph", "call", "xref", "offset",
		}
		for _, check := range patchIndicators {
			if strings.Contains(bodyLower, check) {
				findings = append(findings, &models.Finding{
					Title:       "Reverse - Binary Patch Diff Endpoint",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Payload:     "binary diff request",
					Evidence:    fmt.Sprintf("Binary diff endpoint responds (matched: '%s', status: %d)", check, resp.StatusCode),
					Description: fmt.Sprintf("Binary patch diffing endpoint at %s. Can identify security patch gaps for 0-day hunting (Patch Tuesday analysis).", path),
					Remediation: "Restrict binary diff endpoints. Do not expose patch gap analysis results externally.",
					CWEID:       "CWE-200",
					ModuleID:    "reverse",
				})
				break
			}
		}

		if resp.StatusCode == 200 && len(resp.Body) > 100 {
			for _, critical := range []string{"cve", "CVE-", "vulnerability", "exploit", "0day", "zero-day"} {
				if strings.Contains(bodyLower, critical) {
					findings = append(findings, &models.Finding{
						Title:       "Reverse - Patch Diff with CVE/Exploit References",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Patch diff endpoint contains exploit references (matched: '%s')", critical),
						Description: fmt.Sprintf("Binary patch diff endpoint at %s returns CVE/exploit references. May enable 0-day vulnerability discovery from patch analysis.", path),
						Remediation: "Restrict access to patch diff results. Do not expose vulnerability references externally.",
						CWEID:       "CWE-200",
						ModuleID:    "reverse",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *ReverseModule) checkBinaryScannerEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	scannerPaths := []string{
		"/scan-binary", "/api/scan", "/binary-vuln", "/api/binary-vuln",
		"/vuln-scan", "/api/vuln-scan", "/bin-scan", "/binary-check",
		"/vulnerability-scan", "/security-scan",
	}
	for _, path := range scannerPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"binary":"test.exe","checks":["strcpy","system","execve","gets","sprintf"]}`)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		vulnIndicators := []string{"strcpy", "system", "execve", "gets", "sprintf",
			"strcat", "scanf", "buffer", "overflow", "format",
			"injection", "shellcode", "dangerous", "unsafe",
			"vulnerability", "cve", "warning", "error",
		}
		for _, check := range vulnIndicators {
			if strings.Contains(bodyLower, check) {
				findings = append(findings, &models.Finding{
					Title:       "Reverse - Binary Vulnerability Scanner",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Payload:     "binary scan with dangerous function detection",
					Evidence:    fmt.Sprintf("Binary vulnerability scanner responds (matched: '%s', status: %d)", check, resp.StatusCode),
					Description: fmt.Sprintf("Binary vulnerability scanning endpoint at %s checks for dangerous functions (strcpy, system, execve). Can identify exploitable binaries.", path),
					Remediation: "Restrict binary scanner endpoints. Use internal-only for development. Patch identified vulnerabilities before release.",
					CWEID:       "CWE-200",
					ModuleID:    "reverse",
				})
				break
			}
		}

		if resp.StatusCode == 200 && len(resp.Body) > 50 {
			dangerousCount := 0
			for _, d := range []string{"strcpy", "strcat", "sprintf", "gets", "scanf", "system", "execve", "popen"} {
				if strings.Contains(bodyLower, d) {
					dangerousCount++
				}
			}
			if dangerousCount >= 3 {
				findings = append(findings, &models.Finding{
					Title:       "Reverse - Multiple Dangerous Functions Detected",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Binary scan found %d dangerous function references", dangerousCount),
					Description: fmt.Sprintf("Binary vulnerability scanner at %s detected multiple dangerous C functions. High likelihood of exploitable memory corruption vulnerabilities.", path),
					Remediation: "Replace dangerous functions with safe alternatives (strlcpy, snprintf, etc.). Use compiler flags like -fstack-protector. Enable ASLR and DEP.",
					CWEID:       "CWE-676",
					ModuleID:    "reverse",
				})
			}
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&ReverseModule{})
}
