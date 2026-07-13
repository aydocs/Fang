package http

import (
	"net/http"
	"strings"
	"sync"

	"github.com/aydocs/fang/pkg/models"
)

type CookieJar struct {
	mu      sync.RWMutex
	cookies map[string][]*models.Cookie
}

func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string][]*models.Cookie),
	}
}

func (j *CookieJar) SetCookies(u *http.Request, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()

	domain := u.URL.Hostname()
	for _, c := range cookies {
		jc := &models.Cookie{
			Name:   c.Name,
			Value:  c.Value,
			Domain: c.Domain,
			Path:   c.Path,
			Secure: c.Secure,
		}
		if c.HttpOnly {
			jc.HttpOnly = true
		}
		key := j.cookieKey(domain, c.Name)
		j.cookies[key] = append(j.cookies[key], jc)
	}
}

func (j *CookieJar) Cookies(u *http.Request) []*http.Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	domain := u.URL.Hostname()
	var result []*http.Cookie

	for key, cookies := range j.cookies {
		if !j.matchDomain(key, domain) {
			continue
		}
		for _, c := range cookies {
			result = append(result, &http.Cookie{
				Name:   c.Name,
				Value:  c.Value,
				Domain: c.Domain,
				Path:   c.Path,
				Secure: c.Secure,
			})
		}
	}
	return result
}

func (j *CookieJar) GetAll() map[string][]*models.Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	result := make(map[string][]*models.Cookie, len(j.cookies))
	for k, v := range j.cookies {
		cookies := make([]*models.Cookie, len(v))
		copy(cookies, v)
		result[k] = cookies
	}
	return result
}

func (j *CookieJar) Set(cookies []*models.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()

	for _, c := range cookies {
		key := j.cookieKey(c.Domain, c.Name)
		j.cookies[key] = append(j.cookies[key], c)
	}
}

func (j *CookieJar) cookieKey(domain, name string) string {
	return domain + "|" + name
}

func (j *CookieJar) matchDomain(key, domain string) bool {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return false
	}
	cookieDomain := parts[0]
	if cookieDomain == "" {
		return false
	}
	if cookieDomain == domain {
		return true
	}
	cookieDomain = strings.TrimPrefix(cookieDomain, ".")
	domain = strings.TrimPrefix(domain, ".")
	if cookieDomain == domain {
		return true
	}
	return strings.HasSuffix(domain, "."+cookieDomain)
}

func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string][]*models.Cookie)
}
