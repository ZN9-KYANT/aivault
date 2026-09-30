// Package audit appends JSONL events to ~/.aivault/audit.log (SPEC 4.5).
// Secrets are never logged (SPEC 8.4). Entries are linked into a tamper-
// evident hash chain (learned from pi-llm-gateway): each entry's ID is the
// SHA-256 of the previous entry's ID plus the canonical entry content, so
// edits or deletions break the chain and `audit --verify` reports them.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event names (SPEC 4.5).
const (
	EventUnlock         = "unlock"
	EventLock           = "lock"
	EventKeyAdd         = "key.add"
	EventKeyRemove      = "key.remove"
	EventKeyRotate      = "key.rotate"
	EventKeyUse         = "key.use"
	EventProxyKeyCreate = "proxykey.create"
	EventProviderAdd    = "provider.add"
	EventPasswd         = "passwd"
	EventAuthFail       = "auth.fail"
)

// Entry is one JSONL record in audit.log (SPEC 4.5). Prev/ID form the
// tamper-evident chain: ID = SHA-256(Prev + canonical-content); legacy
// entries written before the chain existed have both empty.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Event      string    `json:"event"`
	Provider   string    `json:"provider,omitempty"`
	ProxyKeyID string    `json:"proxy_key_id,omitempty"`
	Outcome    string    `json:"outcome"`
	Prev       string    `json:"prev,omitempty"`
	ID         string    `json:"id,omitempty"`
}

// entryContent is the canonical (chain-input) projection of Entry: every
// field except Prev/ID, marshaled in fixed field order.
type entryContent struct {
	Timestamp  time.Time `json:"timestamp"`
	Event      string    `json:"event"`
	Provider   string    `json:"provider,omitempty"`
	ProxyKeyID string    `json:"proxy_key_id,omitempty"`
	Outcome    string    `json:"outcome"`
}

// ComputeID returns the chained ID for an entry given its predecessor's ID
// (empty for the first chained entry).
func ComputeID(prev string, e Entry) string {
	content, err := json.Marshal(entryContent{
		Timestamp: e.Timestamp, Event: e.Event, Provider: e.Provider,
		ProxyKeyID: e.ProxyKeyID, Outcome: e.Outcome,
	})
	if err != nil {
		// Fields are plain strings/time — marshal cannot realistically fail.
		content = []byte(fmt.Sprintf("%s|%s|%s|%s", e.Timestamp.UTC().Format(time.RFC3339Nano), e.Event, e.Provider, e.Outcome))
	}
	h := sha256.New()
	_, _ = h.Write([]byte(prev))
	_, _ = h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// writeMu serializes in-process Log calls so the chain is never cut by
// interleaved writers of the same process. Cross-process writes (CLI and
// server running concurrently) remain a documented limitation: verification
// detects the resulting break as a normal tamper report.
var writeMu sync.Mutex

// Log appends one chained entry to the audit log at path, creating it 0600
// if needed.
func Log(path string, e Entry) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer f.Close()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	e.Prev = lastEntryID(f)
	e.ID = ComputeID(e.Prev, e)
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	return nil
}

// lastEntryID scans the tail of an open audit file for the final parsable
// entry's chain ID ("" when absent — legacy entries have none).
func lastEntryID(f *os.File) string {
	const w = 64 << 10
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return ""
	}
	off := int64(0)
	if st.Size() > w {
		off = st.Size() - w
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var e Entry
		if json.Unmarshal([]byte(lines[i]), &e) == nil && e.ID != "" {
			return e.ID
		}
	}
	return ""
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

// Result reports the outcome of Verify.
type Result struct {
	Entries    int // total lines parsed
	ChainLen   int // entries carrying a chained ID
	Legacy     int // pre-chain entries (no ID), skipped
	OK         bool
	FirstBreak int // 1-based line of the first chain violation; 0 when OK
	Detail     string
}

// Verify walks the whole log and checks the ID chain: every chained entry
// must reference the previous chained entry and hash to its own content.
// Legacy (pre-chain) entries are skipped; the chain starts at the first
// entry carrying an ID. A missing log yields an OK empty result.
func Verify(path string) (*Result, error) {
	res := &Result{OK: true}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prevID := ""
	for line := 1; sc.Scan(); line++ {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit: verify line %d: %w", line, err)
		}
		res.Entries++
		if e.ID == "" {
			res.Legacy++
			continue
		}
		res.ChainLen++
		if e.Prev != prevID {
			res.OK, res.FirstBreak = false, line
			res.Detail = fmt.Sprintf("line %d: prev-chain mismatch (want %.16s…, got %.16s…)", line, prevID, e.Prev)
			return res, nil
		}
		if want := ComputeID(e.Prev, e); want != e.ID {
			res.OK, res.FirstBreak = false, line
			res.Detail = fmt.Sprintf("line %d: ID mismatch (content altered?)", line)
			return res, nil
		}
		prevID = e.ID
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: verify read: %w", err)
	}
	return res, nil
}
