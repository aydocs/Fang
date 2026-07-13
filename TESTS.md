All 67 modules now have unit tests. Each test file validates:
- Module ID (ensures `ID()` returns the expected string)
- Module Severity (ensures `Severity()` returns the expected level)
- Module Init (ensures `Init()` succeeds with a standard config)
- Scan graceful degradation (for modules with remote targets — ensures `Scan()` fails gracefully on unreachable targets)
- Module-specific tests where applicable (merkezi `makeFinding`, engine config builder `NewConfig`)

Total: 67 module test files × 3–5 test functions each = ~250 module validation tests.
