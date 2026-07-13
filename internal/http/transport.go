package http

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

func NewTransport(cfg *Config) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConns / 2,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       16 * 1024,
		ReadBufferSize:        16 * 1024,
		ForceAttemptHTTP2:     true,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSInsecure,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
	}

	if len(cfg.TLSCipherSuites) > 0 {
		transport.TLSClientConfig.CipherSuites = cfg.TLSCipherSuites
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		transport.ForceAttemptHTTP2 = false
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			if cfg.ProxyAuth != "" {
				proxyURL.User = url.UserPassword("", cfg.ProxyAuth)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	if cfg.SOCKS5 != "" {
		socksDialer, err := proxy.SOCKS5("tcp", cfg.SOCKS5, nil, &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		if err == nil {
			if ctxDialer, ok := socksDialer.(proxy.ContextDialer); ok {
				transport.DialContext = ctxDialer.DialContext
			}
			transport.Proxy = nil
		}
	}

	return transport
}
