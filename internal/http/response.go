package http

import (
	"net/http"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type Response struct {
	StatusCode int
	Status     string
	Headers    http.Header
	Body       string
	BodyBytes  []byte
	BodyLength int
	URL        string
	Redirect   string
	Cookies    []*models.Cookie
	TLS        *TLSInfo
	Duration   time.Duration
	Request    *RequestInfo
}

type RequestInfo struct {
	Method  string
	URL     string
	Headers http.Header
	Body    string
}

type TLSInfo struct {
	Version     string
	Cipher      string
	Certificate *CertificateInfo
}

type CertificateInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	DNSNames   []string
	SelfSigned bool
}

func tlsVersionString(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
