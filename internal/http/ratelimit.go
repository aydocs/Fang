package http

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	rate   int
	burst  int
	tokens int
	mu     sync.Mutex
	ticker *time.Ticker
	done   chan struct{}
}

func NewRateLimiter(rate int) *RateLimiter {
	if rate <= 0 {
		rate = 50
	}
	burst := rate
	if burst < 1 {
		burst = 1
	}
	rl := &RateLimiter{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		done:   make(chan struct{}),
	}
	if rate > 0 {
		rl.ticker = time.NewTicker(time.Second / time.Duration(rate))
		go rl.refill()
	}
	return rl
}

func (rl *RateLimiter) refill() {
	defer rl.ticker.Stop()
	for {
		select {
		case <-rl.ticker.C:
			rl.mu.Lock()
			if rl.tokens < rl.burst {
				rl.tokens++
			}
			rl.mu.Unlock()
		case <-rl.done:
			return
		}
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl.rate <= 0 {
		return nil
	}

	rl.mu.Lock()
	if rl.tokens > 0 {
		rl.tokens--
		rl.mu.Unlock()
		return nil
	}
	rl.mu.Unlock()

	timer := time.NewTimer(time.Second / time.Duration(rl.rate))
	defer timer.Stop()

	select {
	case <-timer.C:
		rl.mu.Lock()
		if rl.tokens > 0 {
			rl.tokens--
		}
		rl.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Stop() {
	close(rl.done)
}
