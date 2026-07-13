package crawler

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type Config struct {
	MaxDepth          int
	MaxPages          int
	MaxConcurrency    int
	Timeout           time.Duration
	FollowRedirects   bool
	IncludeSubdomains bool
	RespectRobotsTxt  bool
	CrawlStaticFiles  bool
	ExtractJS         bool
	ExtractAPI        bool
	Headers           map[string]string
	Cookies           []*models.Cookie
	UserAgent         string
}

type Crawler struct {
	client *fanghttp.Client
	config *Config
	once   sync.Once
}

type crawlTask struct {
	url   string
	depth int
}

type crawlState struct {
	mu           sync.Mutex
	visited      map[string]bool
	urls         []string
	forms        []*models.Form
	scripts      []string
	stylesheets  []string
	apis         []string
	hiddenInputs []*models.FormInput
	comments     []string
	pages        int
}

func newCrawlState() *crawlState {
	return &crawlState{
		visited: make(map[string]bool),
	}
}

type sitemapURL struct {
	Loc string `xml:"loc"`
}

type urlSet struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapIndex struct {
	XMLName  xml.Name     `xml:"sitemapindex"`
	Sitemaps []sitemapURL `xml:"sitemap"`
}

type fetchResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
	URL        string
	Redirect   string
	Cookies    []*http.Cookie
}

func defaultConfig() *Config {
	return &Config{
		MaxDepth:          2,
		MaxPages:          50,
		MaxConcurrency:    10,
		Timeout:           10 * time.Second,
		FollowRedirects:   true,
		IncludeSubdomains: false,
		RespectRobotsTxt:  true,
		CrawlStaticFiles:  false,
		ExtractJS:         true,
		ExtractAPI:        true,
		UserAgent:         "Fang/1.0 (Security Scanner)",
		Headers:           make(map[string]string),
	}
}

func (c *Crawler) ID() string {
	return "crawler"
}

func (c *Crawler) Name() string {
	return "Crawler"
}

func (c *Crawler) Description() string {
	return "Web crawling, link discovery, and attack surface mapping"
}

func (c *Crawler) Severity() models.Severity {
	return models.Info
}

func (c *Crawler) Init(ctx context.Context, cfg *engine.Config) error {
	if cfg != nil {
		c.config = &Config{
			MaxDepth:          2,
			MaxPages:          50,
			MaxConcurrency:    cfg.Threads,
			Timeout:           cfg.Timeout,
			FollowRedirects:   true,
			IncludeSubdomains: false,
			RespectRobotsTxt:  true,
			CrawlStaticFiles:  false,
			ExtractJS:         true,
			ExtractAPI:        true,
			Headers:           cfg.Headers,
			Cookies:           cfg.Cookies,
			UserAgent:         "Fang/1.0 (Security Scanner)",
		}
	}
	if c.config == nil {
		c.config = defaultConfig()
	}
	c.client = fanghttp.NewClient(fanghttp.WithTimeout(c.config.Timeout))
	return nil
}

func (c *Crawler) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	if target.CrawlResult != nil {
		return nil, nil
	}

	c.once.Do(func() {
		if c.config == nil {
			c.config = defaultConfig()
		}
		if c.client == nil {
			c.client = fanghttp.NewClient(fanghttp.WithTimeout(c.config.Timeout))
		}
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	state := newCrawlState()
	filter := NewFilter()
	baseDomain := ExtractDomain(target.URL)

	var robots *RobotsParser
	if c.config.RespectRobotsTxt {
		if resp, err := c.fetch(ctx, target.URL+"/robots.txt"); err == nil {
			robots = ParseRobots(resp.Body)
			for _, sitemapURL := range robots.Sitemaps() {
				if err := c.fetchSitemap(ctx, sitemapURL, state); err == nil {
					continue
				}
			}
		}
	}

	if c.config.CrawlStaticFiles {
		filter.fileExtensions = make(map[string]bool)
	}

	var workerWg sync.WaitGroup
	var taskWg sync.WaitGroup
	jobs := make(chan crawlTask, c.config.MaxConcurrency*2)

	for i := 0; i < c.config.MaxConcurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-jobs:
					if !ok {
						return
					}
					c.processTask(ctx, task, target.URL, baseDomain, state, filter, robots, jobs, &taskWg)
				}
			}
		}()
	}

	taskWg.Add(1)
	select {
	case <-ctx.Done():
		taskWg.Done()
	case jobs <- crawlTask{url: target.URL, depth: 0}:
	}

	go func() {
		taskWg.Wait()
		cancel()
	}()

	workerWg.Wait()
	close(jobs)

	result := &models.CrawlResult{
		URLs:        state.urls,
		Forms:       state.forms,
		Scripts:     state.scripts,
		Stylesheets: state.stylesheets,
		APIs:        state.apis,
	}
	if len(result.URLs) > 0 {
		result.Body = result.URLs[0]
	}

	target.CrawlResult = result

	return c.buildFindings(state, baseDomain), nil
}

func (c *Crawler) processTask(ctx context.Context, task crawlTask, baseURL string, baseDomain string, state *crawlState, filter *Filter, robots *RobotsParser, jobs chan<- crawlTask, taskWg *sync.WaitGroup) {
	defer taskWg.Done()

	normalized := NormalizeURL(task.url, baseURL)

	state.mu.Lock()
	if state.visited[normalized] {
		state.mu.Unlock()
		return
	}
	if state.pages >= c.config.MaxPages {
		state.mu.Unlock()
		return
	}
	state.visited[normalized] = true
	state.pages++
	state.urls = append(state.urls, normalized)
	state.mu.Unlock()

	if robots != nil && !robots.IsAllowed(task.url) {
		return
	}

	if !IsSameDomain(normalized, baseURL) && !c.config.IncludeSubdomains {
		return
	}

	resp, err := c.fetch(ctx, normalized)
	if err != nil {
		return
	}

	body := resp.Body

	links := ParseLinks(body, normalized)
	forms := ParseForms(body)
	scripts := ParseScripts(body)
	comments := ParseComments(body)
	metaRedirect := ParseMetaRedirect(body)

	var formInputs []*models.FormInput
	for _, form := range forms {
		for _, input := range form.Inputs {
			if input.Type == "hidden" {
				formInputs = append(formInputs, input)
			}
		}
	}

	for _, link := range links {
		if link != "" && filter.ShouldCrawl(link) && !strings.HasPrefix(link, "#") {
			domain := ExtractDomain(link)
			if domain == baseDomain || (c.config.IncludeSubdomains && strings.HasSuffix(domain, "."+baseDomain)) {
				taskWg.Add(1)
				select {
				case <-ctx.Done():
					taskWg.Done()
					return
				case jobs <- crawlTask{url: link, depth: task.depth + 1}:
				}
			}
		}
	}

	if metaRedirect != "" {
		redirectURL := ResolveURL(metaRedirect, normalized)
		if redirectURL != "" && filter.ShouldCrawl(redirectURL) {
			taskWg.Add(1)
			select {
			case <-ctx.Done():
				taskWg.Done()
				return
			case jobs <- crawlTask{url: redirectURL, depth: task.depth + 1}:
			}
		}
	}

	state.mu.Lock()
	state.forms = append(state.forms, forms...)
	state.scripts = append(state.scripts, scripts...)
	state.hiddenInputs = append(state.hiddenInputs, formInputs...)
	state.comments = append(state.comments, comments...)

	for _, s := range scripts {
		resolved := ResolveURL(s, normalized)
		if strings.HasSuffix(resolved, ".js") && !state.visited[resolved] {
			if jsResp, err := c.fetch(ctx, resolved); err == nil {
				if c.config.ExtractJS {
					jsEndpoints := ExtractJSEndpoints(jsResp.Body)
					state.apis = append(state.apis, jsEndpoints...)
				}
				if c.config.ExtractAPI {
					apiPatterns := ExtractAPIPatterns(jsResp.Body)
					state.apis = append(state.apis, apiPatterns...)
				}
			}
		}
	}

	if c.config.ExtractAPI {
		apiPatterns := ExtractAPIPatterns(body)
		state.apis = append(state.apis, apiPatterns...)
	}
	state.mu.Unlock()
}

func (c *Crawler) fetch(ctx context.Context, urlStr string) (*fetchResponse, error) {
	freq := fanghttp.NewRequest("GET", urlStr).WithContext(ctx)
	for k, v := range c.config.Headers {
		freq.Headers[k] = v
	}
	for _, cookie := range c.config.Cookies {
		freq.WithCookie(cookie)
	}

	resp, err := c.client.Do(freq)
	if err != nil {
		return nil, err
	}

	cookies := make([]*http.Cookie, len(resp.Cookies))
	for i, c := range resp.Cookies {
		cookies[i] = &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		}
	}

	return &fetchResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		URL:        resp.URL,
		Redirect:   resp.Redirect,
		Cookies:    cookies,
	}, nil
}

func (c *Crawler) fetchSitemap(ctx context.Context, sitemapURL string, state *crawlState) error {
	resp, err := c.fetch(ctx, sitemapURL)
	if err != nil {
		return err
	}

	urls := parseSitemap(resp.Body)
	state.mu.Lock()
	state.urls = append(state.urls, urls...)
	for _, u := range urls {
		state.visited[NormalizeURL(u, "")] = true
	}
	state.mu.Unlock()

	return nil
}

func parseSitemap(body string) []string {
	var urls []string

	var us urlSet
	if err := xml.Unmarshal([]byte(body), &us); err == nil && len(us.URLs) > 0 {
		for _, u := range us.URLs {
			if u.Loc != "" {
				urls = append(urls, u.Loc)
			}
		}
		if len(urls) > 0 {
			return urls
		}
	}

	var si sitemapIndex
	if err := xml.Unmarshal([]byte(body), &si); err == nil && len(si.Sitemaps) > 0 {
		for _, s := range si.Sitemaps {
			if s.Loc != "" {
				urls = append(urls, s.Loc)
			}
		}
	}

	return urls
}

var sensitiveCommentPattern = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|token|auth|credential|private|key|username|login|db[_-]?pass|database[_-]?url|connection[_-]?string)`)

func (c *Crawler) buildFindings(state *crawlState, baseDomain string) []*models.Finding {
	var findings []*models.Finding

	if len(state.urls) > 0 {
		findings = append(findings, &models.Finding{
			Title:       "Crawl Summary",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			Description: fmt.Sprintf("Discovered %d pages, %d forms, %d scripts, %d API endpoints on %s", len(state.urls), len(state.forms), len(state.scripts), len(state.apis), baseDomain),
			Remediation: "Review crawled pages for sensitive information exposure",
			ModuleID:    c.ID(),
		})
	}

	seenAPI := make(map[string]bool)
	for _, api := range state.apis {
		normalized := strings.TrimSpace(api)
		if normalized == "" || seenAPI[normalized] {
			continue
		}
		seenAPI[normalized] = true
		findings = append(findings, &models.Finding{
			Title:       "API Endpoint Discovered",
			Severity:    models.Info,
			Confidence:  models.MediumConfidence,
			URL:         normalized,
			Description: fmt.Sprintf("API endpoint or pattern discovered: %s", normalized),
			Remediation: "Ensure API endpoints are properly authenticated and rate-limited",
			ModuleID:    c.ID(),
		})
	}

	if len(state.hiddenInputs) > 0 {
		hiddenSummary := summarizeInputs(state.hiddenInputs)
		findings = append(findings, &models.Finding{
			Title:       "Hidden Input Fields Discovered",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			Description: fmt.Sprintf("Found %d hidden input fields: %s", len(state.hiddenInputs), hiddenSummary),
			Remediation: "Review hidden fields for sensitive data exposure",
			ModuleID:    c.ID(),
		})
	}

	for _, comment := range state.comments {
		if sensitiveCommentPattern.MatchString(comment) {
			truncated := comment
			if len(truncated) > 200 {
				truncated = truncated[:200] + "..."
			}
			findings = append(findings, &models.Finding{
				Title:       "Sensitive Data in HTML Comment",
				Severity:    models.Low,
				Confidence:  models.MediumConfidence,
				Evidence:    truncated,
				Description: "HTML comment contains potentially sensitive information",
				Remediation: "Remove sensitive data from HTML comments before deployment",
				ModuleID:    c.ID(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, &models.Finding{
			Title:       "No Crawl Results",
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			Description: fmt.Sprintf("No pages were crawled on %s", baseDomain),
			Remediation: "",
			ModuleID:    c.ID(),
		})
	}

	return findings
}

func summarizeInputs(inputs []*models.FormInput) string {
	var names []string
	for _, inp := range inputs {
		if inp.Name != "" {
			names = append(names, inp.Name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("%d hidden fields", len(inputs))
	}
	return fmt.Sprintf("%d fields: %s", len(inputs), strings.Join(names, ", "))
}

var _ engine.Module = (*Crawler)(nil)

func init() {
	engine.GetRegistry().Register(&Crawler{})
}
