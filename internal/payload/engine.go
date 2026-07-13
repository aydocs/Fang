package payload

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aydocs/fang/pkg/models"
)

type Engine struct {
	store    *Store
	encoders []Encoder
	mu       sync.RWMutex
}

func NewEngine() *Engine {
	return &Engine{
		store:    NewStore(),
		encoders: make([]Encoder, 0),
	}
}

func (e *Engine) Generate(ctx context.Context, param *models.Parameter, vulnType string) ([]*models.Payload, error) {
	categories := e.store.GetByVulnType(vulnType)
	if len(categories) == 0 {
		return nil, nil
	}

	var payloads []*models.Payload
	for _, cat := range categories {
		for _, entry := range cat.Payloads {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			p := &models.Payload{
				Value:   entry.Value,
				Encoded: entry.Value,
				Type:    vulnType,
			}

			if entry.Encoder != "" {
				if enc := e.getEncoder(entry.Encoder); enc != nil {
					p.Encoded = enc.Encode(entry.Value)
				}
			}

			e.applyEntryParams(p, entry)

			if param != nil {
				p.Params = append(p.Params, param.Name)
			}

			payloads = append(payloads, p)
		}
	}

	return payloads, nil
}

func (e *Engine) GenerateWithContext(ctx context.Context, param *models.Parameter, vulnType string, tech string, waf string) ([]*models.Payload, error) {
	payloads, err := e.Generate(ctx, param, vulnType)
	if err != nil {
		return nil, err
	}

	ctxType := "html"
	if param != nil {
		ctxType = DetectContext(param.Value, param.Name)
	}

	var results []*models.Payload
	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if tech != "" {
			tagsMatch := false
			for _, cat := range e.store.GetByVulnType(vulnType) {
				for _, entry := range cat.Payloads {
					if entry.Value == p.Value {
						for _, tag := range entry.Tags {
							if strings.EqualFold(tag, tech) {
								tagsMatch = true
								break
							}
						}
						break
					}
				}
				if tagsMatch {
					break
				}
			}
			if !tagsMatch {
				contextPayload := &models.Payload{
					Value:   p.Value,
					Encoded: p.Encoded,
					Type:    p.Type,
					Context: ctxType,
					Params:  p.Params,
					Headers: p.Headers,
					Cookies: p.Cookies,
				}
				results = append(results, contextPayload)
				continue
			}
		}

		injected := InjectInContext(ctxType, p.Value)
		contextPayload := &models.Payload{
			Value:   injected,
			Encoded: p.Encoded,
			Type:    p.Type,
			Context: ctxType,
			Params:  p.Params,
			Headers: p.Headers,
			Cookies: p.Cookies,
		}
		results = append(results, contextPayload)
	}

	if waf != "" {
		var wafVariants []*models.Payload
		mutator := NewMutator(e.encoders)
		for _, p := range results {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			wafMutations, err := mutator.MutateWithWAF(ctx, p, waf, 3)
			if err != nil {
				continue
			}
			wafVariants = append(wafVariants, wafMutations...)
		}
		results = append(results, wafVariants...)
	}

	return results, nil
}

func (e *Engine) RegisterEncoder(enc Encoder) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.encoders = append(e.encoders, enc)
}

func (e *Engine) LoadCategories(dir string) error {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, payloadDir)
	}

	if err := createDefaultPayloads(dir); err != nil {
		return fmt.Errorf("failed to create default payloads: %w", err)
	}

	if err := e.store.Load(dir); err != nil {
		return fmt.Errorf("failed to load payloads: %w", err)
	}

	return nil
}

func (e *Engine) Store() *Store {
	return e.store
}

func (e *Engine) getEncoder(name string) Encoder {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, enc := range e.encoders {
		if strings.EqualFold(enc.Name(), name) {
			return enc
		}
	}
	return nil
}

func (e *Engine) applyEntryParams(p *models.Payload, entry *Entry) {
	if entry.Params == nil {
		return
	}
	for k, v := range entry.Params {
		if strings.HasPrefix(k, "header_") {
			if p.Headers == nil {
				p.Headers = make(map[string]string)
			}
			p.Headers[strings.TrimPrefix(k, "header_")] = v
		} else if strings.HasPrefix(k, "cookie_") {
			if p.Cookies == nil {
				p.Cookies = make(map[string]string)
			}
			p.Cookies[strings.TrimPrefix(k, "cookie_")] = v
		} else {
			if p.Headers == nil {
				p.Headers = make(map[string]string)
			}
			p.Headers[k] = v
		}
	}
}
