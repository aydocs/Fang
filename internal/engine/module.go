package engine

import (
	"context"

	"github.com/aydocs/fang/pkg/models"
)

type Module interface {
	ID() string
	Name() string
	Description() string
	Severity() models.Severity
	Init(ctx context.Context, cfg *Config) error
	Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error)
}
