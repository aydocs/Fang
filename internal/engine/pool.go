package engine

import (
	"context"
	"sync"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type WorkerPool struct {
	workers  int
	jobs     chan Job
	results  chan *models.ModuleResult
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once
	logger   *Logger
	cfg      *Config
}

type Job struct {
	Module Module
	Target *models.Target
}

func NewWorkerPool(ctx context.Context, workers int, logger *Logger, cfg *Config) *WorkerPool {
	ctx, cancel := context.WithCancel(ctx)
	return &WorkerPool{
		workers: workers,
		jobs:    make(chan Job, workers*2),
		results: make(chan *models.ModuleResult, workers*2),
		ctx:     ctx,
		cancel:  cancel,
		logger:  logger,
		cfg:     cfg,
	}
}

func (p *WorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

func (p *WorkerPool) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			result := p.execute(job)
			select {
			case <-p.ctx.Done():
				return
			case p.results <- result:
			}
		}
	}
}

func (p *WorkerPool) execute(job Job) *models.ModuleResult {
	if p.cfg != nil {
		if err := job.Module.Init(p.ctx, p.cfg); err != nil && p.logger != nil {
			p.logger.Error("module %s init error: %v", job.Module.Name(), err)
		}
	}
	if p.logger != nil {
		p.logger.ModuleStart(job.Module.Name())
	}
	start := time.Now()
	findings, err := job.Module.Scan(p.ctx, job.Target)
	duration := time.Since(start)
	if p.logger != nil {
		if err != nil {
			p.logger.Error("module %s error: %v", job.Module.Name(), err)
		} else {
			p.logger.ModuleComplete(job.Module.Name(), len(findings), duration)
		}
	}
	return &models.ModuleResult{
		ModuleID:   job.Module.ID(),
		ModuleName: job.Module.Name(),
		Findings:   findings,
		Error:      err,
		Duration:   duration,
	}
}

func (p *WorkerPool) Submit(job Job) {
	select {
	case <-p.ctx.Done():
		return
	case p.jobs <- job:
	}
}

func (p *WorkerPool) Results() <-chan *models.ModuleResult {
	return p.results
}

func (p *WorkerPool) Stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		p.wg.Wait()
		close(p.jobs)
		close(p.results)
	})
}
