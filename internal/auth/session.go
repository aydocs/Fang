package auth

import "net/http"

type Session struct {
	Cookies   []*http.Cookie
	Headers   map[string]string
	BasicUser string
	BasicPass string
	Bearer    string
	CSRF      string
}

func NewSession() *Session {
	return &Session{
		Cookies: make([]*http.Cookie, 0),
		Headers: make(map[string]string),
	}
}

func (s *Session) ApplyToRequest(req *http.Request) {
	if s == nil {
		return
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	for _, c := range s.Cookies {
		req.AddCookie(c)
	}
	if s.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+s.Bearer)
	} else if s.BasicUser != "" || s.BasicPass != "" {
		req.SetBasicAuth(s.BasicUser, s.BasicPass)
	}
	if s.CSRF != "" {
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			req.Header.Set("X-CSRF-Token", s.CSRF)
		}
	}
}

func (s *Session) FromResponse(resp *http.Response) {
	if s == nil || resp == nil {
		return
	}
	s.Cookies = append(s.Cookies, resp.Cookies()...)
}

func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	cp := &Session{
		BasicUser: s.BasicUser,
		BasicPass: s.BasicPass,
		Bearer:    s.Bearer,
		CSRF:      s.CSRF,
		Headers:   make(map[string]string, len(s.Headers)),
		Cookies:   make([]*http.Cookie, len(s.Cookies)),
	}
	for k, v := range s.Headers {
		cp.Headers[k] = v
	}
	copy(cp.Cookies, s.Cookies)
	return cp
}
