package models

import (
	"testing"
)

func TestCWEToOWASP(t *testing.T) {
	tests := []struct {
		cwe    string
		expect string
	}{
		{"CWE-89", "A1:2021 - SQL Injection"},
		{"CWE-79", "A3:2021 - Cross-Site Scripting"},
		{"CWE-22", "A1:2021 - Path Traversal"},
		{"CWE-78", "A1:2021 - OS Command Injection"},
		{"CWE-918", "A1:2021 - Server-Side Request Forgery"},
		{"CWE-611", "A1:2021 - XML External Entity (XXE)"},
		{"CWE-502", "A1:2021 - Deserialization Attack"},
		{"CWE-287", "A7:2021 - Authentication Bypass"},
		{"CWE-200", "A4:2021 - Information Disclosure"},
		{"CWE-352", "A1:2021 - Cross-Site Request Forgery"},
		{"CWE-400", "A6:2021 - Resource Exhaustion (DoS)"},
		{"CWE-444", "A1:2021 - HTTP Request Smuggling"},
		{"CWE-601", "A1:2021 - Open Redirect"},
		{"CWE-1321", "A1:2021 - Prototype Pollution"},
		{"CWE-943", "A1:2021 - NoSQL Injection"},
		{"CWE-UNKNOWN", "A6:2021 - Security Misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.cwe, func(t *testing.T) {
			got := CWEToOWASP(tt.cwe)
			if got != tt.expect {
				t.Errorf("CWEToOWASP(%q) = %q, want %q", tt.cwe, got, tt.expect)
			}
		})
	}
}

func TestCWEToCVSS(t *testing.T) {
	tests := []struct {
		cwe    string
		expect float64
	}{
		{"CWE-89", 9.8},
		{"CWE-79", 6.1},
		{"CWE-22", 7.5},
		{"CWE-78", 9.8},
		{"CWE-918", 9.8},
		{"CWE-611", 9.8},
		{"CWE-502", 9.8},
		{"CWE-200", 5.3},
		{"CWE-352", 8.8},
		{"CWE-400", 7.5},
		{"CWE-UNKNOWN", 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.cwe, func(t *testing.T) {
			got := CWEToCVSS(tt.cwe)
			if got != tt.expect {
				t.Errorf("CWEToCVSS(%q) = %v, want %v", tt.cwe, got, tt.expect)
			}
		})
	}
}

func TestEnrichFinding(t *testing.T) {
	f := &Finding{
		Title: "Test Finding",
		CWEID: "CWE-89",
	}
	EnrichFinding(f)
	if f.OWASPCategory != "A1:2021 - SQL Injection" {
		t.Errorf("expected OWASP SQL Injection, got %q", f.OWASPCategory)
	}
	if f.CVSS == nil || *f.CVSS != 9.8 {
		t.Errorf("expected CVSS 9.8, got %v", f.CVSS)
	}
}

func TestEnrichFindingPreservesExisting(t *testing.T) {
	v := 7.5
	f := &Finding{
		Title:         "Test Finding",
		CWEID:         "CWE-89",
		OWASPCategory: "Custom Category",
		CVSS:          &v,
	}
	EnrichFinding(f)
	if f.OWASPCategory != "Custom Category" {
		t.Errorf("expected existing OWASP preserved, got %q", f.OWASPCategory)
	}
	if f.CVSS == nil || *f.CVSS != 7.5 {
		t.Errorf("expected existing CVSS preserved, got %v", f.CVSS)
	}
}
