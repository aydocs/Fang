package db

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/aydocs/fang/pkg/models"
	"github.com/google/uuid"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	db = nil
	dir := t.TempDir()
	cfg := &Config{
		Path: filepath.Join(dir, "test.db"),
	}
	_, err := Open(cfg)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("failed to disable foreign keys: %v", err)
	}
}

func teardownTestDB() {
	if db != nil {
		db.Close()
		db = nil
	}
	once = sync.Once{}
}

func TestOpenAndMigrate(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	if DB() == nil {
		t.Fatal("expected non-nil db after Open")
	}
}

func TestCreateAndGetTarget(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	id, err := CreateTarget("https://example.com", "example.com", "Example", "", "")
	if err != nil {
		t.Fatalf("CreateTarget failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty id")
	}

	target, err := GetTarget(id)
	if err != nil {
		t.Fatalf("GetTarget failed: %v", err)
	}
	if target.URL != "https://example.com" {
		t.Errorf("target url = %q, want https://example.com", target.URL)
	}
}

func TestCreateAndListTargets(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	CreateTarget("https://a.com", "a.com", "A", "", "")
	CreateTarget("https://b.com", "b.com", "B", "", "")

	targets, err := ListTargets()
	if err != nil {
		t.Fatalf("ListTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}
}

func TestDeleteTarget(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	id, _ := CreateTarget("https://example.com", "", "Test", "", "")
	if err := DeleteTarget(id); err != nil {
		t.Fatalf("DeleteTarget failed: %v", err)
	}

	_, err := GetTarget(id)
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestCreateAndQueryScans(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	targetID, _ := CreateTarget("https://example.com", "", "", "", "")
	scanID, err := CreateScan(targetID, nil, 10, 5, "", "test", "")
	if err != nil {
		t.Fatalf("CreateScan failed: %v", err)
	}
	if scanID == "" {
		t.Fatal("expected non-empty scan id")
	}

	scan, err := GetScan(scanID)
	if err != nil {
		t.Fatalf("GetScan failed: %v", err)
	}
	if scan.Status != "pending" {
		t.Errorf("scan status = %q, want pending", scan.Status)
	}
}

func TestUpdateScanStatus(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	targetID, _ := CreateTarget("https://example.com", "", "", "", "")
	scanID, _ := CreateScan(targetID, nil, 10, 5, "", "test", "")

	if err := UpdateScanStatus(scanID, "completed", ""); err != nil {
		t.Fatalf("UpdateScanStatus failed: %v", err)
	}

	scan, _ := GetScan(scanID)
	if scan.Status != "completed" {
		t.Errorf("scan status = %q, want completed", scan.Status)
	}
}

func TestCreateUser(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	id, err := CreateUser("testuser", "test@example.com", "password123", "user")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty user id")
	}
}

func TestQueryFindings(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	scanID := uuid.New().String()
	targetID := uuid.New().String()

	findings := []*models.Finding{
		{Title: "SQL Injection", Severity: models.Critical, Confidence: models.HighConfidence, CWEID: "CWE-89", ModuleID: "sqli"},
		{Title: "XSS", Severity: models.Medium, Confidence: models.HighConfidence, CWEID: "CWE-79", ModuleID: "xss"},
	}

	for _, f := range findings {
		_, err := db.Exec(
			`INSERT INTO findings (id, scan_id, target_id, module_id, title, severity, confidence, cwe_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			uuid.New().String(), scanID, targetID, f.ModuleID, f.Title, f.Severity.String(), f.Confidence.String(), f.CWEID,
		)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}

	results, err := QueryFindings(FindingFilter{ScanID: scanID, Limit: 10})
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 findings, got %d", len(results))
	}
}

func TestSeverityStats(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	scanID := uuid.New().String()

	for _, sev := range []string{"CRITICAL", "CRITICAL", "HIGH", "MEDIUM"} {
		db.Exec(
			`INSERT INTO findings (id, scan_id, target_id, module_id, title, severity, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			uuid.New().String(), scanID, "t1", "test", "Test", sev, "HIGH",
		)
	}

	stats, err := GetSeverityStats()
	if err != nil {
		t.Fatalf("GetSeverityStats failed: %v", err)
	}
	if stats["CRITICAL"] != 2 {
		t.Errorf("expected 2 critical, got %d", stats["CRITICAL"])
	}
}

func TestCreateSchedule(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	id, err := CreateSchedule("target-1", "Nightly Scan", "0 2 * * *", "", "critical", "", "user-1")
	if err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty id")
	}

	schedules, err := ListSchedules()
	if err != nil {
		t.Fatalf("ListSchedules failed: %v", err)
	}
	if len(schedules) != 1 {
		t.Errorf("expected 1 schedule, got %d", len(schedules))
	}
}

func TestDeleteSchedule(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	id, _ := CreateSchedule("target-1", "Test", "*/5 * * * *", "", "all", "", "user-1")
	if err := DeleteSchedule(id); err != nil {
		t.Fatalf("DeleteSchedule failed: %v", err)
	}
}
