package inject

import (
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

func TestSQLIErrorPayloads(t *testing.T) {
	payloads := SQLIErrorPayloads()
	if len(payloads) == 0 {
		t.Fatal("expected non-empty SQLI error payloads")
	}
	t.Logf("loaded %d SQLI error payloads", len(payloads))
}

func TestSQLIErrorPatterns(t *testing.T) {
	patterns := SQLIErrorPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected non-empty SQLI error patterns")
	}
	t.Logf("loaded %d SQLI error patterns", len(patterns))
}

func TestXSSPayloads(t *testing.T) {
	payloads := XSSPayloads()
	if len(payloads) == 0 {
		t.Fatal("expected non-empty XSS payloads")
	}
	t.Logf("loaded %d XSS payloads", len(payloads))
}

func TestLFIPayloads(t *testing.T) {
	payloads := LFIPathTraversal()
	if len(payloads) == 0 {
		t.Fatal("expected non-empty LFI payloads")
	}
	t.Logf("loaded %d LFI payloads", len(payloads))
}

func TestSSRFCheckURLs(t *testing.T) {
	urls := SSRFInternalIPs()
	if len(urls) == 0 {
		t.Fatal("expected non-empty SSRF URLs")
	}
	t.Logf("loaded %d SSRF URLs", len(urls))
}

func TestCommandInjectionPayloads(t *testing.T) {
	payloads := CMDIUnixPayloads()
	if len(payloads) == 0 {
		t.Fatal("expected non-empty command injection payloads")
	}
	t.Logf("loaded %d cmd injection payloads", len(payloads))
}

func TestOpenRedirectPayloads(t *testing.T) {
	payloads := RedirectPayloads()
	if len(payloads) == 0 {
		t.Fatal("expected non-empty redirect payloads")
	}
	t.Logf("loaded %d redirect payloads", len(payloads))
}

func TestHeaderInjectionPayloads(t *testing.T) {
	if len(SecurityHeaders) == 0 {
		t.Fatal("expected non-empty security headers")
	}
	t.Logf("loaded %d security headers", len(SecurityHeaders))
}

func TestUniqueMarker(t *testing.T) {
	m1 := UniqueMarker("test")
	m2 := UniqueMarker("test")
	if m1 == m2 {
		t.Error("consecutive markers should be unique")
	}
	t.Logf("markers: %s, %s", m1, m2)
}

func TestCandidateParams(t *testing.T) {
	params := CandidateParams
	if len(params) == 0 {
		t.Fatal("expected non-empty candidate params")
	}
}

func TestBuildTestURL(t *testing.T) {
	url := BuildTestURL("http://test.com/page.php", "id", "1")
	if url != "http://test.com/page.php?id=1" {
		t.Errorf("BuildTestURL = %q, want http://test.com/page.php?id=1", url)
	}
}

func TestBuildTestURLWithExistingParam(t *testing.T) {
	url := BuildTestURL("http://test.com/page.php?foo=bar", "id", "1")
	if url != "http://test.com/page.php?foo=bar&id=1" {
		t.Errorf("BuildTestURL = %q", url)
	}
}

func TestTrimParamValue(t *testing.T) {
	result := TrimParamValue("' OR '1'='1", 50)
	if result == "" {
		t.Error("trimmed result is empty")
	}
}

func TestTargetParams(t *testing.T) {
	params := TargetParams(&models.Target{URL: "http://test.com/page.php?id=1&name=test"})
	if len(params) != 2 {
		t.Errorf("expected 2 params, got %d", len(params))
	}
}

func TestNoSQLPayloads(t *testing.T) {
	payloads := NoSQLPayloads()
	if len(payloads) > 0 {
		t.Logf("loaded %d NoSQL payloads", len(payloads))
	}
}

func TestXXEPayloads(t *testing.T) {
	payloads := XXEClassicPayloads()
	if len(payloads) > 0 {
		t.Logf("loaded %d XXE payloads", len(payloads))
	}
}
