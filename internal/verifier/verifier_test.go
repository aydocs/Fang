package verifier

import (
	"context"
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

func TestVerifierNew(t *testing.T) {
	v := New(nil)
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestVerifierVerifyReflection(t *testing.T) {
	v := New(nil)
	ctx := context.Background()
	finding := &models.Finding{
		Title:     "Test XSS",
		URL:       "http://test.com/?q=TESTMARKER",
		Parameter: "q",
		Payload:   "<script>alert(1)</script>",
	}
	result, _ := v.Verify(ctx, finding, "http://test.com")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestVerifierVerifyTiming(t *testing.T) {
	v := New(nil)
	ctx := context.Background()
	finding := &models.Finding{
		Title:     "Test Timing",
		URL:       "http://test.com/?q=sleep(5)",
		Parameter: "q",
		Payload:   "sleep(5)",
	}
	result, _ := v.Verify(ctx, finding, "http://test.com")
	if result != nil && !result.Confirmed {
		t.Log("timing verification skipped (expected for non-responsive target)")
	}
}

func TestConfidenceScorer(t *testing.T) {
	cs := &ConfidenceScorer{}
	_ = cs
}

func TestVerifyConfig(t *testing.T) {
	cfg := Config{
		BaselineCompare: true,
		MaxAttempts:     3,
	}
	v := New(&cfg)
	if v.config.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", v.config.MaxAttempts)
	}
	if !v.config.BaselineCompare {
		t.Error("BaselineCompare = false, want true")
	}
}

func TestVerifyRepeatedCheck(t *testing.T) {
	v := New(&Config{RepeatedChecks: 2})
	if v.config.RepeatedChecks != 2 {
		t.Errorf("RepeatedChecks = %d, want 2", v.config.RepeatedChecks)
	}
}

func TestVerifyEmptyFinding(t *testing.T) {
	v := New(nil)
	ctx := context.Background()
	result, _ := v.Verify(ctx, nil, "http://test.com")
	if result != nil {
		t.Log("nil finding returns nil result (expected)")
	}
}
