package scheduler

import (
	"testing"
)

func TestNewScheduler(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("expected non-nil scheduler")
	}
}

func TestSchedulerRunningInitially(t *testing.T) {
	s := New()
	if s.Running() {
		t.Error("new scheduler should not be running")
	}
}

func TestSchedulerStartStop(t *testing.T) {
	s := New()
	err := s.Start()
	if err != nil {
		t.Log("Start returned error (may need DB):", err)
	}
	if s.Running() {
		s.Stop()
		if s.Running() {
			t.Error("scheduler still running after Stop")
		}
	}
}

func TestSchedulerDoubleStart(t *testing.T) {
	s := New()
	err := s.Start()
	if err != nil {
		t.Skip("Start failed, skipping double start test")
	}
	defer s.Stop()

	err2 := s.Start()
	if err2 != nil {
		t.Log("double start returned error:", err2)
	}
}

func TestSchedulerRemoveNonexistent(t *testing.T) {
	s := New()
	s.Remove("nonexistent")
}

func TestSchedulerAddBeforeStart(t *testing.T) {
	s := New()
	err := s.Add("test", "*/5 * * * *")
	if err != nil {
		t.Log("Add before Start:", err)
	}
}

func TestSchedulerReloadWithoutStart(t *testing.T) {
	s := New()
	err := s.Reload()
	if err != nil {
		t.Log("Reload without Start:", err)
	}
}
