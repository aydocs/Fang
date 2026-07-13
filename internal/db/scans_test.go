package db

import (
	"testing"
)

func TestScanFilterDefaults(t *testing.T) {
	f := ScanFilter{}
	if f.Limit != 0 {
		t.Errorf("Limit = %d, want 0", f.Limit)
	}
}

func TestScanFilterWithValues(t *testing.T) {
	f := ScanFilter{
		TargetID: "test-id",
		Status:   "completed",
		Limit:    10,
		Offset:   5,
	}
	if f.TargetID != "test-id" {
		t.Errorf("TargetID = %s, want test-id", f.TargetID)
	}
	if f.Limit != 10 {
		t.Errorf("Limit = %d, want 10", f.Limit)
	}
}

func TestJoinConditions(t *testing.T) {
	result := joinConditions([]string{"a = 1", "b = 2"}, " AND ")
	if result != "a = 1 AND b = 2" {
		t.Errorf("joinConditions = %q, want 'a = 1 AND b = 2'", result)
	}
}

func TestJoinQuoted(t *testing.T) {
	result := joinQuoted([]string{"a", "b"})
	if result != "'a','b'" {
		t.Errorf("joinQuoted = %q, want 'a','b'", result)
	}
}

func TestJoinConditionsSingle(t *testing.T) {
	result := joinConditions([]string{"a = 1"}, " AND ")
	if result != "a = 1" {
		t.Errorf("joinConditions single = %q", result)
	}
}

func TestFindingFilterDefaults(t *testing.T) {
	f := FindingFilter{}
	if f.Limit != 0 {
		t.Errorf("Limit = %d, want 0", f.Limit)
	}
}

func TestNullString(t *testing.T) {
	ns := nullString("test")
	if !ns.Valid {
		t.Error("nullString('test'): Valid = false")
	}
	if ns.String != "test" {
		t.Errorf("String = %q, want 'test'", ns.String)
	}

	empty := nullString("")
	if empty.Valid {
		t.Error("nullString(''): Valid = true")
	}
}

func TestNullFloat(t *testing.T) {
	v := 3.14
	nf := nullFloat(&v)
	if !nf.Valid {
		t.Error("nullFloat(&v): Valid = false")
	}
	if nf.Float64 != 3.14 {
		t.Errorf("Float64 = %f, want 3.14", nf.Float64)
	}

	zero := nullFloat(nil)
	if zero.Valid {
		t.Error("nullFloat(nil): Valid = true")
	}
}

func TestScheduleRow(t *testing.T) {
	r := ScheduleRow{
		ID:       "sched-1",
		TargetID: "target-1",
		Name:     "Daily Scan",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}
	if !r.Enabled {
		t.Error("Enabled = false, want true")
	}
	if r.CronExpr != "0 0 * * *" {
		t.Errorf("CronExpr = %q", r.CronExpr)
	}
}

func TestUserRow(t *testing.T) {
	r := UserRow{
		ID:       "user-1",
		Username: "testuser",
		Email:    "test@test.com",
		Role:     "admin",
	}
	if r.Role != "admin" {
		t.Errorf("Role = %q, want admin", r.Role)
	}
}
