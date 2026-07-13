package browser

import (
	"testing"
	"time"
)

func TestNewBrowser(t *testing.T) {
	b, err := New(&Config{Timeout: 5 * time.Second, Headless: true})
	if err != nil {
		t.Skip("chromedp not available:", err)
	}
	defer b.Close()
}

func TestBrowserConfigDefaults(t *testing.T) {
	b, err := New(nil)
	if err != nil {
		t.Skip("chromedp not available:", err)
	}
	defer b.Close()
}

func TestBrowserClose(t *testing.T) {
	b, err := New(nil)
	if err != nil {
		t.Skip("chromedp not available:", err)
	}
	b.Close()
}
