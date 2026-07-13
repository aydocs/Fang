package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Notifier struct {
	client *http.Client
}

type Notification struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Message string `json:"message"`
	ScanID  string `json:"scan_id,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	Channel string `json:"channel"`
}

func New() *Notifier {
	return &Notifier{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) Send(notif *Notification) error {
	switch notif.Channel {
	case "webhook":
		return n.sendWebhook(notif)
	default:
		return n.sendInApp(notif)
	}
}

func (n *Notifier) sendWebhook(notif *Notification) error {
	body, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("marshal notif: %w", err)
	}

	webhookURL := notif.Message
	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fang-Notifier/1.0")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}

func (n *Notifier) sendInApp(notif *Notification) error {
	log.Printf("[notification] %s: %s", notif.Type, notif.Title)
	return nil
}

func (n *Notifier) NotifyScanComplete(scanID, targetURL string, findingCount int) {
	_ = n.Send(&Notification{
		Type:    "scan_complete",
		Title:   fmt.Sprintf("Scan Complete: %s", targetURL),
		Message: fmt.Sprintf("Found %d findings", findingCount),
		ScanID:  scanID,
		Channel: "in_app",
	})
}

func (n *Notifier) NotifyScanFailed(scanID, targetURL, errMsg string) {
	_ = n.Send(&Notification{
		Type:    "scan_error",
		Title:   fmt.Sprintf("Scan Failed: %s", targetURL),
		Message: errMsg,
		ScanID:  scanID,
		Channel: "in_app",
	})
}
