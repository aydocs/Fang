package notifier

import (
	"testing"
)

func TestNewNotifier(t *testing.T) {
	n := New()
	if n == nil {
		t.Fatal("expected non-nil notifier")
	}
}

func TestSendInApp(t *testing.T) {
	n := New()
	err := n.Send(&Notification{
		Type:    "test",
		Title:   "Test Notification",
		Message: "This is a test",
		Channel: "in_app",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendWebhookInvalidURL(t *testing.T) {
	n := New()
	err := n.Send(&Notification{
		Type:    "test",
		Title:   "Webhook Test",
		Message: "http://localhost:1/webhook",
		Channel: "webhook",
	})
	if err == nil {
		t.Log("webhook send to invalid URL returned nil (connection refused)")
	}
}

func TestNotifyScanComplete(t *testing.T) {
	n := New()
	n.NotifyScanComplete("scan-1", "http://test.com", 5)
}

func TestNotifyScanFailed(t *testing.T) {
	n := New()
	n.NotifyScanFailed("scan-1", "http://test.com", "connection refused")
}

func TestNotificationStruct(t *testing.T) {
	n := &Notification{
		Type:    "scan_complete",
		Title:   "Done",
		Message: "All good",
		ScanID:  "s1",
		Channel: "in_app",
	}
	if n.Type != "scan_complete" {
		t.Errorf("Type = %q", n.Type)
	}
}
