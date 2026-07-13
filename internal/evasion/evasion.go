package evasion

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"sync"
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
)

type EvasionConfig struct {
	ProxyRotation bool          `json:"proxy_rotation"`
	ProxyList     []string      `json:"proxy_list"`
	TorEnabled    bool          `json:"tor_enabled"`
	RandomUA      bool          `json:"random_ua"`
	Fingerprint   bool          `json:"fingerprint"`
	AdaptiveDelay bool          `json:"adaptive_delay"`
	MinDelay      time.Duration `json:"min_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
}

type Engine struct {
	config   *EvasionConfig
	proxies  []string
	proxyIdx int
	client   *fanghttp.Client
	lastReq  time.Time
	mu       sync.Mutex
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Vivaldi/6.7",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}

var tlsProfiles = [][]uint16{
	{
		tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	{
		tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	{
		tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	},
}

func (e *Engine) fingerprintOpts() []fanghttp.Option {
	if !e.config.Fingerprint {
		return nil
	}
	profile := tlsProfiles[rand.Intn(len(tlsProfiles))]
	return []fanghttp.Option{fanghttp.WithCipherSuites(profile...)}
}

func New(cfg *EvasionConfig) *Engine {
	if cfg == nil {
		cfg = &EvasionConfig{
			MinDelay: 500 * time.Millisecond,
			MaxDelay: 3000 * time.Millisecond,
		}
	}
	if cfg.MinDelay == 0 {
		cfg.MinDelay = 500 * time.Millisecond
	}
	if cfg.MaxDelay == 0 {
		cfg.MaxDelay = 3000 * time.Millisecond
	}

	e := &Engine{
		config:  cfg,
		proxies: make([]string, len(cfg.ProxyList)),
	}
	copy(e.proxies, cfg.ProxyList)

	httpOpts := []fanghttp.Option{
		fanghttp.WithTimeout(30 * time.Second),
		fanghttp.WithFollowRedirects(true),
	}

	if len(e.fingerprintOpts()) > 0 {
		httpOpts = append(httpOpts, e.fingerprintOpts()...)
	}

	if cfg.TorEnabled {
		httpOpts = append(httpOpts, fanghttp.WithSOCKS5("127.0.0.1:9050"))
	}

	if len(e.proxies) > 0 {
		httpOpts = append(httpOpts, fanghttp.WithProxy(e.proxies[0]))
	}

	e.client = fanghttp.NewClient(httpOpts...)
	return e
}

func (e *Engine) GetClient() *fanghttp.Client {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config.ProxyRotation && len(e.proxies) > 0 {
		e.proxyIdx = (e.proxyIdx + 1) % len(e.proxies)
		proxy := e.proxies[e.proxyIdx]
		opts := []fanghttp.Option{
			fanghttp.WithTimeout(30 * time.Second),
			fanghttp.WithFollowRedirects(true),
		}
		if e.config.TorEnabled {
			opts = append(opts, fanghttp.WithSOCKS5("127.0.0.1:9050"))
		}
		opts = append(opts, fanghttp.WithProxy(proxy))
		opts = append(opts, e.fingerprintOpts()...)
		e.client = fanghttp.NewClient(opts...)
	}

	if e.config.RandomUA {
		ua := userAgents[rand.Intn(len(userAgents))]
		e.client.Config().UserAgent = ua
	}

	return e.client
}

func (e *Engine) RotateProxy() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.proxies) == 0 {
		return
	}

	e.proxyIdx = (e.proxyIdx + 1) % len(e.proxies)
	proxy := e.proxies[e.proxyIdx]

	opts := []fanghttp.Option{
		fanghttp.WithTimeout(30 * time.Second),
		fanghttp.WithFollowRedirects(true),
	}
	opts = append(opts, fanghttp.WithProxy(proxy))

	if e.config.TorEnabled {
		opts = append(opts, fanghttp.WithSOCKS5("127.0.0.1:9050"))
	}

	opts = append(opts, e.fingerprintOpts()...)
	e.client = fanghttp.NewClient(opts...)
}

func (e *Engine) GetUserAgent() string {
	if !e.config.RandomUA {
		return "Fang/1.0 (Security Scanner)"
	}
	return userAgents[rand.Intn(len(userAgents))]
}

func (e *Engine) WaitDelay() {
	if !e.config.AdaptiveDelay {
		return
	}

	e.mu.Lock()
	last := e.lastReq
	e.mu.Unlock()

	if last.IsZero() {
		e.mu.Lock()
		e.lastReq = time.Now()
		e.mu.Unlock()
		return
	}

	delay := time.Duration(rand.Int63n(int64(e.config.MaxDelay-e.config.MinDelay))) + e.config.MinDelay

	elapsed := time.Since(last)
	if elapsed < delay {
		time.Sleep(delay - elapsed)
	}

	e.mu.Lock()
	e.lastReq = time.Now()
	e.mu.Unlock()
}

func (e *Engine) SetTransport(rt http.RoundTripper) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.client.Config().Proxy = ""
}

func (e *Engine) Config() *EvasionConfig {
	return e.config
}

func (e *Engine) UpdateConfig(cfg *EvasionConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}
