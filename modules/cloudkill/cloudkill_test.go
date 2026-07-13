package cloudkill

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCloudKillModuleID(t *testing.T) {
	m := &CloudKillModule{}
	if m.ID() != "cloudkill" {
		t.Errorf("ID = %q, want cloudkill", m.ID())
	}
}

func TestCloudKillModuleName(t *testing.T) {
	m := &CloudKillModule{}
	if m.Name() == "" {
		t.Error("Name should not be empty")
	}
}

func TestCloudKillModuleSeverity(t *testing.T) {
	m := &CloudKillModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestCloudKillModuleInit(t *testing.T) {
	m := &CloudKillModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCloudKillScanGraceful(t *testing.T) {
	m := &CloudKillModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}

func TestCandidateNames(t *testing.T) {
	m := &CloudKillModule{host: "example.com"}
	names := m.candidateNames()
	if len(names) == 0 {
		t.Fatal("candidateNames returned empty")
	}
	if names[0] != "example-com" {
		t.Errorf("First candidate = %q, want example-com", names[0])
	}
}

func TestMinS(t *testing.T) {
	if minS(5, 10) != 5 {
		t.Error("minS(5, 10) should be 5")
	}
	if minS(10, 5) != 5 {
		t.Error("minS(10, 5) should be 5")
	}
	if minS(5, 5) != 5 {
		t.Error("minS(5, 5) should be 5")
	}
}
