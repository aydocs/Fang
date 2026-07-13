package models

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s      Severity
		expect string
	}{
		{Info, "INFO"},
		{Low, "LOW"},
		{Medium, "MEDIUM"},
		{High, "HIGH"},
		{Critical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			if got := tt.s.String(); got != tt.expect {
				t.Errorf("Severity.String() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestSeverityColor(t *testing.T) {
	if got := Critical.Color(); got != "red" {
		t.Errorf("Critical.Color() = %q, want red", got)
	}
	if got := Info.Color(); got != "white" {
		t.Errorf("Info.Color() = %q, want white", got)
	}
}

func TestConfidenceString(t *testing.T) {
	tests := []struct {
		c      Confidence
		expect string
	}{
		{Tentative, "TENTATIVE"},
		{LowConfidence, "LOW"},
		{MediumConfidence, "MEDIUM"},
		{HighConfidence, "HIGH"},
		{CriticalConfidence, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			if got := tt.c.String(); got != tt.expect {
				t.Errorf("Confidence.String() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestNewFinding(t *testing.T) {
	f := NewFinding("Test", Critical)
	if f.Title != "Test" {
		t.Errorf("NewFinding title = %q, want Test", f.Title)
	}
	if f.Severity != Critical {
		t.Errorf("NewFinding severity = %v, want Critical", f.Severity)
	}
	if f.Confidence != HighConfidence {
		t.Errorf("NewFinding confidence = %v, want HighConfidence", f.Confidence)
	}
}

func TestSummaryAdd(t *testing.T) {
	s := &Summary{}
	s.Add(&Finding{Title: "Test", Severity: Critical})
	s.Add(&Finding{Title: "Test2", Severity: High})
	s.Add(&Finding{Title: "Test3", Severity: Info})

	if s.Total != 3 {
		t.Errorf("Summary total = %d, want 3", s.Total)
	}
	if s.Critical != 1 {
		t.Errorf("Summary critical = %d, want 1", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("Summary high = %d, want 1", s.High)
	}
	if s.Info != 1 {
		t.Errorf("Summary info = %d, want 1", s.Info)
	}
}
