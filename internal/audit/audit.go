// Package audit writes an append-only JSONL log of every tool call the
// gateway routes, including denied ones.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Record is one audited tool call.
type Record struct {
	Time     time.Time       `json:"time"`
	CallID   string          `json:"call_id"`
	Wormhole string          `json:"wormhole"`
	Tool     string          `json:"tool"`
	Decision string          `json:"decision"` // "allow" or "deny"
	Reason   string          `json:"reason,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	// Targets maps each linked port to the target the call was routed
	// through, capturing the full resolved chain for the record.
	Targets  map[string]string `json:"targets,omitempty"`
	IsError  bool              `json:"is_error,omitempty"`
	Error    string            `json:"error,omitempty"`
	Duration time.Duration     `json:"duration_ns,omitempty"`
}

// Log is a concurrency-safe JSONL appender.
type Log struct {
	mu sync.Mutex
	w  io.WriteCloser
}

// Open appends to the file at path, creating it if needed.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	return &Log{w: f}, nil
}

// Discard returns a log that drops all records (for tests).
func Discard() *Log {
	return &Log{w: nopCloser{io.Discard}}
}

// Write appends one record. Failures must not block gateway operation, so
// they are reported on stderr rather than returned.
func (l *Log) Write(r Record) {
	line, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: marshaling record: %v\n", err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "audit: writing record: %v\n", err)
	}
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Close()
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
