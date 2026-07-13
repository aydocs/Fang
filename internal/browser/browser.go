package browser

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

type Config struct {
	Timeout  time.Duration
	Headless bool
}

type Browser struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func New(cfg *Config) (*Browser, error) {
	if cfg == nil {
		cfg = &Config{Timeout: 30 * time.Second, Headless: true}
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", cfg.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("mute-audio", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	_, cancel := chromedp.NewContext(allocCtx)
	_ = cancel
	ctx, ctxCancel := context.WithTimeout(allocCtx, cfg.Timeout)

	b := &Browser{ctx: ctx, cancel: func() { ctxCancel(); allocCancel() }}
	return b, nil
}

func (b *Browser) Close() {
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *Browser) Navigate(url string) (string, error) {
	var html string
	err := chromedp.Run(b.ctx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
		chromedp.OuterHTML("html", &html),
	)
	if err != nil {
		return "", fmt.Errorf("navigate: %w", err)
	}
	return html, nil
}

func (b *Browser) Evaluate(expr string) (string, error) {
	var result string
	err := chromedp.Run(b.ctx,
		chromedp.Evaluate(expr, &result),
	)
	if err != nil {
		return "", fmt.Errorf("evaluate: %w", err)
	}
	return result, nil
}

func (b *Browser) Screenshot(url string) ([]byte, error) {
	var buf []byte
	err := chromedp.Run(b.ctx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
		chromedp.FullScreenshot(&buf, 90),
	)
	if err != nil {
		return nil, fmt.Errorf("screenshot: %w", err)
	}
	return buf, nil
}

func (b *Browser) ConsoleLogs(url string) ([]string, error) {
	var logs []string
	chromedp.ListenTarget(b.ctx, func(ev interface{}) {
	})
	err := chromedp.Run(b.ctx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
	)
	if err != nil {
		return nil, fmt.Errorf("console logs: %w", err)
	}
	return logs, nil
}
