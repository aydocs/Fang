# Contributing to Fang

## Getting Started

Fork the repository and clone your fork locally. Make sure you have Go 1.21+ and Node.js 18+ installed.

## Development Setup

1. Install Go dependencies: `go mod tidy`
2. Install frontend dependencies: `cd frontend && npm install`
3. Build the project: `go build ./...`
4. Run tests: `go test ./...`

For frontend development:
```bash
cd frontend
npm run dev
```

## Module Development Guide

Each security module must implement the `engine.Module` interface:

```go
type Module interface {
    ID() string
    Name() string
    Description() string
    Severity() models.Severity
    Scan(ctx context.Context, target *models.Target) (*models.ModuleResult, error)
}
```

Place new modules in `internal/vulnmodules/` and register them in the engine registry.

## Code Standards

- No comments in source code
- All text in English
- Every module must implement engine.Module interface
- Tests required for all new code
- Run `go vet ./...` before submitting PRs
- Follow idiomatic Go conventions (gofmt)
- Use meaningful variable and function names

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for your changes
3. Ensure all tests pass
4. Update documentation if needed
5. Submit a PR with a clear description of changes

## Reporting Issues

Use the GitHub issue tracker. Include steps to reproduce, expected behavior, and actual behavior.
