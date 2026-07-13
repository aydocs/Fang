package race

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type RaceModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *RaceModule) ID() string   { return "race" }
func (m *RaceModule) Name() string { return "Race Condition Testing Module" }
func (m *RaceModule) Description() string {
	return "TOCTOU, parallel request race, double-spend, payment race, rate-limit race, database race, and concurrency vulnerability detection"
}
func (m *RaceModule) Severity() models.Severity { return models.High }

type raceTarget struct {
	URL    string
	Method string
	Body   string
	Check  string
	Name   string
}

func (m *RaceModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *RaceModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	targets := m.identifyTargets(target)
	if len(targets) == 0 {
		return nil, nil
	}

	for _, rt := range targets {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		findings = append(findings, m.testConcurrentRace(ctx, rt)...)
		findings = append(findings, m.testTOCTOU(ctx, rt)...)
		findings = append(findings, m.testPaymentRace(ctx, rt)...)
		findings = append(findings, m.testRateLimitRace(ctx, rt)...)
		findings = append(findings, m.testDatabaseRace(ctx, rt)...)
	}

	return findings, nil
}

func (m *RaceModule) testConcurrentRace(ctx context.Context, rt raceTarget) []*models.Finding {
	var findings []*models.Finding

	baselineResp, err := m.client.Get(rt.URL)
	if err != nil {
		return nil
	}

	concurrent := 20
	var wg sync.WaitGroup
	responses := make([]*fanghttp.Response, concurrent)
	errs := make([]error, concurrent)

	wg.Add(concurrent)
	for i := 0; i < concurrent; i++ {
		go func(idx int) {
			defer wg.Done()
			var resp *fanghttp.Response
			var rerr error
			switch rt.Method {
			case "POST":
				req := fanghttp.NewRequest("POST", rt.URL)
				req.Body = rt.Body
				resp, rerr = m.client.Do(req)
			default:
				resp, rerr = m.client.Get(rt.URL)
			}
			responses[idx] = resp
			errs[idx] = rerr
		}(i)
	}
	wg.Wait()

	successCount := 0
	uniqueBodies := make(map[string]int)
	for i, r := range responses {
		if errs[i] != nil {
			continue
		}
		successCount++
		bodyKey := r.Body
		if len(bodyKey) > 100 {
			bodyKey = bodyKey[:100]
		}
		uniqueBodies[bodyKey]++
	}

	if successCount > 1 && len(uniqueBodies) > 1 {
		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("Race Condition - %s", rt.Name),
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         rt.URL,
			Payload:     rt.Body,
			Evidence:    fmt.Sprintf("%d concurrent requests produced %d unique responses (baseline: %d bytes)", concurrent, len(uniqueBodies), len(baselineResp.Body)),
			Description: fmt.Sprintf("Race condition detected on %s. Different responses suggest concurrent access vulnerability.", rt.Name),
			Remediation: "Implement proper locking mechanisms. Use database transactions with serializable isolation. Enforce idempotency keys.",
			CWEID:       "CWE-362",
			ModuleID:    "race",
		})
	}

	if successCount > 3 {
		findings = append(findings, &models.Finding{
			Title:       "Race Condition - High Concurrency Possible",
			Severity:    models.Medium,
			Confidence:  models.LowConfidence,
			URL:         rt.URL,
			Evidence:    fmt.Sprintf("%d of %d requests succeeded concurrently", successCount, concurrent),
			Description: "Target accepts many concurrent requests, which may enable race condition attacks on state-changing operations.",
			Remediation: "Implement rate limiting and request queuing. Use pessimistic locking for financial operations.",
			CWEID:       "CWE-362",
			ModuleID:    "race",
		})
	}

	return findings
}

func (m *RaceModule) testTOCTOU(ctx context.Context, rt raceTarget) []*models.Finding {
	var findings []*models.Finding

	var checkURL string
	if strings.Contains(rt.URL, "?") {
		checkURL = rt.URL + "&check=true"
	} else {
		checkURL = rt.URL + "?check=true"
	}

	checkResp, err := m.client.Get(checkURL)
	if err != nil {
		return nil
	}

	var wg sync.WaitGroup
	useOps := 10
	useResponses := make([]*fanghttp.Response, useOps)
	useErrs := make([]error, useOps)

	wg.Add(useOps)
	for i := 0; i < useOps; i++ {
		go func(idx int) {
			defer wg.Done()
			resp, err := m.client.Post(rt.URL, rt.Body+"&toctou=true")
			useResponses[idx] = resp
			useErrs[idx] = err
		}(i)
	}
	wg.Wait()

	useSuccess := 0
	var useBodies []string
	for i, r := range useResponses {
		if useErrs[i] != nil {
			continue
		}
		useSuccess++
		bodyStr := r.Body
		if len(bodyStr) > 80 {
			bodyStr = bodyStr[:80]
		}
		useBodies = append(useBodies, bodyStr)
	}

	checkBodyLen := len(checkResp.Body)
	if useSuccess > 1 && len(useBodies) > 1 {
		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("TOCTOU - %s", rt.Name),
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         rt.URL,
			Payload:     rt.Body + "&toctou=true",
			Evidence:    fmt.Sprintf("Check returned %d bytes. %d of %d use operations succeeded with different responses", checkBodyLen, useSuccess, useOps),
			Description: fmt.Sprintf("Time-of-Check Time-of-Use (TOCTOU) vulnerability on %s. State changed between check and use operations under concurrent access.", rt.Name),
			Remediation: "Use atomic operations. Implement optimistic locking. Perform check and use in single transaction with serializable isolation.",
			CWEID:       "CWE-367",
			ModuleID:    "race",
		})
	}

	delayedResp, err := m.client.Get(checkURL)
	if err == nil {
		currentBodyLen := len(delayedResp.Body)
		if currentBodyLen != checkBodyLen {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("TOCTOU - State Change Detected (%s)", rt.Name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         rt.URL,
				Evidence:    fmt.Sprintf("State changed between check (%d bytes) and re-check (%d bytes)", checkBodyLen, currentBodyLen),
				Description: fmt.Sprintf("Resource state changed between consecutive reads on %s, indicating TOCTOU vulnerability window.", rt.Name),
				Remediation: "Use atomic compare-and-swap operations. Lock resources during check-and-use sequences.",
				CWEID:       "CWE-367",
				ModuleID:    "race",
			})
		}
	}

	return findings
}

func (m *RaceModule) testPaymentRace(ctx context.Context, rt raceTarget) []*models.Finding {
	var findings []*models.Finding

	paymentPaths := []string{"/checkout", "/api/order", "/api/transfer", "/payment", "/charge", "/redeem", "/coupon", "/wallet/transfer"}
	isPaymentTarget := false
	for _, pp := range paymentPaths {
		if strings.Contains(strings.ToLower(rt.URL), pp) {
			isPaymentTarget = true
			break
		}
	}
	if !isPaymentTarget {
		return nil
	}

	concurrentPayments := 5
	var wg sync.WaitGroup
	paymentResponses := make([]*fanghttp.Response, concurrentPayments)
	paymentErrs := make([]error, concurrentPayments)

	wg.Add(concurrentPayments)
	for i := 0; i < concurrentPayments; i++ {
		go func(idx int) {
			defer wg.Done()
			req := fanghttp.NewRequest("POST", rt.URL)
			req.Body = rt.Body + fmt.Sprintf("&request_id=payment-race-%d-%d", idx, time.Now().UnixNano())
			resp, err := m.client.Do(req)
			paymentResponses[idx] = resp
			paymentErrs[idx] = err
		}(i)
	}
	wg.Wait()

	successPayments := 0
	statusCounts := make(map[int]int)
	for i, r := range paymentResponses {
		if paymentErrs[i] != nil {
			continue
		}
		successPayments++
		statusCounts[r.StatusCode]++
	}

	if successPayments > 1 {
		findings = append(findings, &models.Finding{
			Title:       "Payment Race Condition - Double Spending Possible",
			Severity:    models.Critical,
			Confidence:  models.HighConfidence,
			URL:         rt.URL,
			Payload:     rt.Body,
			Evidence:    fmt.Sprintf("%d concurrent payment requests succeeded. Status codes: %v", successPayments, statusCounts),
			Description: "Payment endpoint accepted multiple concurrent requests, enabling double-spending and race condition attacks on financial transactions.",
			Remediation: "Implement idempotency keys. Use database transactions with serializable isolation. Apply pessimistic locking. Validate balance before and after each transaction.",
			CWEID:       "CWE-362",
			ModuleID:    "race",
		})
	}

	allSameStatus := len(statusCounts) == 1
	if allSameStatus && successPayments > 1 {
		for status, count := range statusCounts {
			if status == 200 || status == 201 {
				_ = count
				findings = append(findings, &models.Finding{
					Title:       "Payment Race - All Concurrent Payments Accepted",
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         rt.URL,
					Evidence:    fmt.Sprintf("All %d concurrent payment requests returned HTTP %d", successPayments, status),
					Description: "All concurrent payment requests were accepted, indicating no race protection on financial operations.",
					Remediation: "Implement server-side idempotency. Use database-level locks. Apply balance checks within transactions.",
					CWEID:       "CWE-362",
					ModuleID:    "race",
				})
			}
		}
	}

	return findings
}

func (m *RaceModule) testRateLimitRace(ctx context.Context, rt raceTarget) []*models.Finding {
	var findings []*models.Finding

	burstCount := 30
	var wg sync.WaitGroup
	successBefore := 0
	var mu sync.Mutex

	wg.Add(burstCount)
	for i := 0; i < burstCount; i++ {
		go func(idx int) {
			defer wg.Done()
			var resp *fanghttp.Response
			var err error
			switch rt.Method {
			case "POST":
				req := fanghttp.NewRequest("POST", rt.URL)
				req.Body = rt.Body + fmt.Sprintf("&rate_race=%d", idx)
				resp, err = m.client.Do(req)
			default:
				resp, err = m.client.Get(rt.URL)
			}
			if err == nil && resp.StatusCode == 200 {
				mu.Lock()
				successBefore++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if successBefore > 10 {
		time.Sleep(100 * time.Millisecond)

		secondBurst := 30
		successAfter := 0
		wg.Add(secondBurst)
		for i := 0; i < secondBurst; i++ {
			go func(idx int) {
				defer wg.Done()
				var resp *fanghttp.Response
				var err error
				switch rt.Method {
				case "POST":
					req := fanghttp.NewRequest("POST", rt.URL)
					req.Body = rt.Body + fmt.Sprintf("&rate_race_2=%d", idx)
					resp, err = m.client.Do(req)
				default:
					resp, err = m.client.Get(rt.URL)
				}
				if err == nil && resp.StatusCode == 200 {
					mu.Lock()
					successAfter++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()

		if successAfter > 10 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Rate-Limit Race Condition - %s", rt.Name),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         rt.URL,
				Evidence:    fmt.Sprintf("First burst: %d/%d success. Second burst: %d/%d success. Rate limiting appears raceable.", successBefore, burstCount, successAfter, secondBurst),
				Description: "Rate limiting can be bypassed via race condition. Concurrent requests before rate limiter engages allow burst attacks.",
				Remediation: "Use atomic counters for rate limiting. Implement sliding window with consistent locking. Apply rate limiting at connection level.",
				CWEID:       "CWE-362",
				ModuleID:    "race",
			})
		}
	}

	return findings
}

func (m *RaceModule) testDatabaseRace(ctx context.Context, rt raceTarget) []*models.Finding {
	var findings []*models.Finding

	dbRacePaths := []string{"/register", "/signup", "/api/user", "/api/resource", "/create", "/update", "/delete", "/api/v1/data"}
	isDBTarget := false
	for _, dp := range dbRacePaths {
		if strings.Contains(strings.ToLower(rt.URL), dp) {
			isDBTarget = true
			break
		}
	}
	if !isDBTarget {
		return nil
	}

	concurrentOps := 10
	var wg sync.WaitGroup
	insertResponses := make([]*fanghttp.Response, concurrentOps)
	insertErrs := make([]error, concurrentOps)

	wg.Add(concurrentOps)
	for i := 0; i < concurrentOps; i++ {
		go func(idx int) {
			defer wg.Done()
			req := fanghttp.NewRequest("POST", rt.URL)
			req.Body = rt.Body + fmt.Sprintf("&unique_key=db-race-%d&data=test-%d", idx, idx)
			resp, err := m.client.Do(req)
			insertResponses[idx] = resp
			insertErrs[idx] = err
		}(i)
	}
	wg.Wait()

	createdCount := 0
	duplicateCount := 0
	errorCount := 0
	for i, r := range insertResponses {
		if insertErrs[i] != nil {
			errorCount++
			continue
		}
		if r.StatusCode == 200 || r.StatusCode == 201 {
			createdCount++
		} else if r.StatusCode == 409 || r.StatusCode == 400 {
			duplicateCount++
		}
	}

	if createdCount > 1 && duplicateCount == 0 {
		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("Database Race Condition - %s", rt.Name),
			Severity:    models.Critical,
			Confidence:  models.HighConfidence,
			URL:         rt.URL,
			Payload:     rt.Body,
			Evidence:    fmt.Sprintf("%d concurrent inserts succeeded, 0 duplicates detected. No unique constraint enforcement observed.", createdCount),
			Description: "Database race condition detected. Concurrent inserts succeeded without unique constraint enforcement, indicating missing or raceable database constraints.",
			Remediation: "Use database unique constraints. Implement pessimistic locking. Use INSERT ... ON CONFLICT or similar atomic operations.",
			CWEID:       "CWE-362",
			ModuleID:    "race",
		})
	}

	if createdCount > 0 && duplicateCount > 0 {
		findings = append(findings, &models.Finding{
			Title:       "Database Race - Partial Duplicate Detection",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         rt.URL,
			Evidence:    fmt.Sprintf("Created: %d, Duplicates: %d, Errors: %d", createdCount, duplicateCount, errorCount),
			Description: "Database shows partial duplicate detection, but race window exists where multiple inserts succeed before constraint is enforced.",
			Remediation: "Use serializable transaction isolation. Implement application-level locking before database writes.",
			CWEID:       "CWE-362",
			ModuleID:    "race",
		})
	}

	return findings
}

func (m *RaceModule) identifyTargets(target *models.Target) []raceTarget {
	targets := []raceTarget{
		{URL: target.URL, Method: "GET", Name: "Parallel GET"},
	}

	forms := []string{"/login", "/register", "/checkout", "/api/order", "/api/transfer", "/coupon", "/redeem", "/vote",
		"/api/user/create", "/api/resource", "/payment", "/charge", "/wallet", "/signup", "/create", "/update"}
	for _, f := range forms {
		targets = append(targets, raceTarget{
			URL:    strings.TrimRight(target.URL, "/") + f,
			Method: "POST",
			Body:   "action=test&race=true",
			Name:   f,
		})
	}

	return targets
}

func init() {
	engine.GetRegistry().Register(&RaceModule{})
}
