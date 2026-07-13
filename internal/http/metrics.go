package http

import (
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	TotalRequests int64
	Successful    int64
	Failed        int64
	Retries       int64
	BytesSent     int64
	BytesReceived int64
	AvgLatency    time.Duration
	mu            sync.Mutex
	latencies     []time.Duration
}

func NewMetrics() *Metrics {
	return &Metrics{
		latencies: make([]time.Duration, 0, 1024),
	}
}

func (m *Metrics) AddRequest() {
	atomic.AddInt64(&m.TotalRequests, 1)
}

func (m *Metrics) AddSuccess() {
	atomic.AddInt64(&m.Successful, 1)
}

func (m *Metrics) AddFailure() {
	atomic.AddInt64(&m.Failed, 1)
}

func (m *Metrics) AddRetry() {
	atomic.AddInt64(&m.Retries, 1)
}

func (m *Metrics) AddBytesSent(n int64) {
	atomic.AddInt64(&m.BytesSent, n)
}

func (m *Metrics) AddBytesReceived(n int64) {
	atomic.AddInt64(&m.BytesReceived, n)
}

func (m *Metrics) AddLatency(d time.Duration) {
	m.mu.Lock()
	m.latencies = append(m.latencies, d)
	m.mu.Unlock()
	m.updateAvgLatency()
}

func (m *Metrics) updateAvgLatency() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.latencies) == 0 {
		m.AvgLatency = 0
		return
	}
	var total time.Duration
	for _, d := range m.latencies {
		total += d
	}
	m.AvgLatency = total / time.Duration(len(m.latencies))
}

func (m *Metrics) Snapshot() Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Metrics{
		TotalRequests: atomic.LoadInt64(&m.TotalRequests),
		Successful:    atomic.LoadInt64(&m.Successful),
		Failed:        atomic.LoadInt64(&m.Failed),
		Retries:       atomic.LoadInt64(&m.Retries),
		BytesSent:     atomic.LoadInt64(&m.BytesSent),
		BytesReceived: atomic.LoadInt64(&m.BytesReceived),
		AvgLatency:    m.AvgLatency,
	}
}

func (m *Metrics) Reset() {
	atomic.StoreInt64(&m.TotalRequests, 0)
	atomic.StoreInt64(&m.Successful, 0)
	atomic.StoreInt64(&m.Failed, 0)
	atomic.StoreInt64(&m.Retries, 0)
	atomic.StoreInt64(&m.BytesSent, 0)
	atomic.StoreInt64(&m.BytesReceived, 0)
	m.mu.Lock()
	m.latencies = m.latencies[:0]
	m.AvgLatency = 0
	m.mu.Unlock()
}
