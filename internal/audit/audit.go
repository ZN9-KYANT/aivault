// Package audit appends JSONL events to ~/.aivault/audit.log (SPEC 4.5).
// Secrets are never logged (SPEC 8.4).
package audit

import (
	"time"

	"github.com/ZN9-KYANT/aivault/internal/errs"
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

// Log appends one entry to the audit log at path (stub).
func Log(path string, e Entry) error { return errs.ErrNotImplemented }

// Tail returns the last n entries from the audit log at path (stub).
func Tail(path string, n int) ([]Entry, error) { return nil, errs.ErrNotImplemented }