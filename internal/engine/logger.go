package engine

import (
	"fmt"
	"sync"
	"time"
)

type Logger struct {
	verbose bool
	mu      sync.Mutex
}

func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("[+] "+format+"\n", args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("[*] "+format+"\n", args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("[!] "+format+"\n", args...)
}

func (l *Logger) ModuleStart(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("\n  [->] %s\n", name)
}

func (l *Logger) ModuleComplete(name string, findings int, dur time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  [OK] %s | %d findings | %s\n", name, findings, dur.Round(time.Millisecond))
}
