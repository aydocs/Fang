package http

import (
	"context"
	"sync"
)

type Pool struct {
	workers int
	jobs    chan *job
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	started bool
	mu      sync.Mutex
}

type job struct {
	request  *Request
	resultCh chan *jobResult
}

type jobResult struct {
	response *Response
	err      error
}

func NewPool(workers int) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		workers: workers,
		jobs:    make(chan *job, workers*2),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (p *Pool) Start(handler func(*Request) (*Response, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return
	}
	p.started = true

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(handler)
	}
}

func (p *Pool) worker(handler func(*Request) (*Response, error)) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case j, ok := <-p.jobs:
			if !ok {
				return
			}
			resp, err := handler(j.request)
			j.resultCh <- &jobResult{response: resp, err: err}
		}
	}
}

func (p *Pool) Execute(req *Request) (*Response, error) {
	resultCh := make(chan *jobResult, 1)
	select {
	case p.jobs <- &job{request: req, resultCh: resultCh}:
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}

	select {
	case result := <-resultCh:
		return result.response, result.err
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

func (p *Pool) Batch(requests []*Request) []*Response {
	type pending struct {
		index int
		ch    chan *jobResult
	}

	pendingJobs := make([]*pending, len(requests))
	for i, req := range requests {
		ch := make(chan *jobResult, 1)
		pendingJobs[i] = &pending{index: i, ch: ch}
		select {
		case p.jobs <- &job{request: req, resultCh: ch}:
		case <-p.ctx.Done():
			responses := make([]*Response, len(requests))
			return responses
		}
	}

	responses := make([]*Response, len(requests))
	for _, pj := range pendingJobs {
		select {
		case result := <-pj.ch:
			if result.err == nil {
				responses[pj.index] = result.response
			}
		case <-p.ctx.Done():
			return responses
		}
	}
	return responses
}

func (p *Pool) Stop() {
	p.cancel()
	p.wg.Wait()
}

func (p *Pool) Close() {
	p.Stop()
	close(p.jobs)
}
