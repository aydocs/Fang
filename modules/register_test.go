package modules

import (
	"testing"

	"github.com/aydocs/fang/internal/engine"
)

func TestAllModulesRegister(t *testing.T) {
	reg := engine.GetRegistry()
	list := reg.List()

	moduleIDs := make(map[string]bool)
	for _, m := range list {
		if moduleIDs[m.ID()] {
			t.Errorf("duplicate module ID: %s", m.ID())
		}
		moduleIDs[m.ID()] = true
	}

	expected := []string{
		"0day", "adcs", "android", "arsenal",
		"bluetooth", "browser",
		"cloud", "cloudkill", "cicd", "cmdi", "cors", "crlf",
		"dataphantom", "deser", "devnull", "docker",
		"endgame", "evasion", "exchange",
		"git", "graphql",
		"headers", "helm",
		"idpwn", "inject", "iot", "ios",
		"k8s", "kerberos",
		"ldap", "lfi",
		"malware", "central", "method",
		"nosqli", "npm", "ntlm",
		"oidc",
		"payment", "phish", "proto",
		"race", "recon", "redirect", "rest", "reverse", "rfid",
		"saml", "sbom", "sdr", "serverless", "shadow", "smb", "smuggler", "soap", "spectre", "sqli", "ssrf", "ssti", "strike",
		"terraform",
		"vpn",
		"websocket", "wifi",
		"xpath", "xss", "xxe",
	}

	for _, id := range expected {
		if !moduleIDs[id] {
			t.Errorf("expected module %s not registered", id)
		}
	}

	if len(list) != len(expected) {
		t.Errorf("expected %d modules, got %d", len(expected), len(list))
	}
}

func TestAllModulesHaveValidMetadata(t *testing.T) {
	list := engine.GetRegistry().List()

	for _, m := range list {
		if m.ID() == "" {
			t.Errorf("module has empty ID: %+v", m)
		}
		if m.Name() == "" {
			t.Errorf("module %s has empty Name", m.ID())
		}
		if m.Description() == "" {
			t.Errorf("module %s has empty Description", m.ID())
		}
		sev := m.Severity()
		if sev < 0 || sev > 4 {
			t.Errorf("module %s has invalid severity: %d", m.ID(), sev)
		}
	}
}

func TestModuleIDUniqueness(t *testing.T) {
	list := engine.GetRegistry().List()
	ids := make(map[string]int)

	for _, m := range list {
		ids[m.ID()]++
	}

	for id, count := range ids {
		if count > 1 {
			t.Errorf("module ID %q registered %d times", id, count)
		}
	}
}

func TestSeverityDistribution(t *testing.T) {
	list := engine.GetRegistry().List()
	counts := make(map[string]int)

	for _, m := range list {
		switch m.Severity() {
		case 0:
			counts["info"]++
		case 1:
			counts["low"]++
		case 2:
			counts["medium"]++
		case 3:
			counts["high"]++
		case 4:
			counts["critical"]++
		}
	}

	if counts["critical"] < 20 {
		t.Errorf("expected at least 20 critical modules, got %d", counts["critical"])
	}
	if counts["info"] < 1 {
		t.Errorf("expected at least 1 info module, got %d", counts["info"])
	}
}
