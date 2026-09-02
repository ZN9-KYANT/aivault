// Package audit appends JSONL events to ~/.aivault/audit.log (SPEC 4.5).
// Secrets are never logged (SPEC 8.4).
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Event names (SPEC 4.5).
const (
	EventUnlock         = "unlock"
	EventLock           = "lock"
	EventKeyAdd         = "key.add"
	EventKeyUse         = "key.use"
	EventProxyKeyCreate = "proxykey.create"
	EventAuthFail       = "auth.fail"
)

// Entry is one JSONL record in audit.log (SPEC 4.5).
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Event      string    `json:"event"`
	Provider   string    `json:"provider,omitempty"`
	ProxyKeyID string    `json:"proxy_key_id,omitempty"`
	Outcome    string    `json:"outcome"`
}

// Log appends one entry to the audit log at path, creating it 0600 if needed.
func Log(path string, e Entry) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer f.Close()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	return nil
}

// Tail returns the last n entries from the audit log at path. A missing log
// yields no entries.
func Tail(path string, n int) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit: parse line %q: %w", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	return entries, nil
}
