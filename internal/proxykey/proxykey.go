// Package proxykey issues and verifies downstream client keys (SPEC 4.4):
// returned once as vk-<48 hex>, stored only as SHA-256 hashes in
// proxykeys.json, and compared in constant time.
package proxykey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// file is the on-disk proxykeys.json schema (SPEC 4.4). Plaintext keys are
// never stored — only SHA-256 digests.
type file struct {
	Version   int   `json:"version"`
	ProxyKeys []Key `json:"proxy_keys"`
}

const fileVersion = 1

// Key is one proxy-key record as stored (hashed) in proxykeys.json (SPEC 4.4).
type Key struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Providers    []string  `json:"providers,omitempty"`
	RPM          int       `json:"rpm,omitempty"`
	MaxUSDPerDay float64   `json:"max_usd_per_day,omitempty"`
	SHA256       string    `json:"sha256"` // hex digest of the vk- key
	CreatedAt    time.Time `json:"created_at"`
	Revoked      bool      `json:"revoked"`
}

// Generate returns a new proxy key: its record and the plaintext key
// (vk-<48 hex>) to show the user exactly once.
func Generate() (*Key, string, error) {
	idBuf := make([]byte, 8)
	keyBuf := make([]byte, 24) // 24 bytes -> 48 hex chars
	if _, err := rand.Read(idBuf); err != nil {
		return nil, "", fmt.Errorf("proxykey: generate id: %w", err)
	}
	if _, err := rand.Read(keyBuf); err != nil {
		return nil, "", fmt.Errorf("proxykey: generate key: %w", err)
	}
	plaintext := "vk-" + hex.EncodeToString(keyBuf)
	sum := sha256.Sum256([]byte(plaintext))
	k := &Key{
		ID:        "pk-" + hex.EncodeToString(idBuf),
		SHA256:    hex.EncodeToString(sum[:]),
		CreatedAt: time.Now(),
	}
	return k, plaintext, nil
}

// Verify reports whether plaintext matches the stored hash, comparing in
// constant time (SPEC 4.4, 8.5).
func Verify(k *Key, plaintext string) bool {
	sum := sha256.Sum256([]byte(plaintext))
	stored, err := hex.DecodeString(k.SHA256)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(sum[:], stored) == 1
}

// Store persists proxy keys to proxykeys.json (SPEC 4.4): SHA-256 hashes
// only, atomic 0600 writes. The gateway re-reads the file per request so CLI
// changes (create/revoke) take effect immediately.
type Store struct {
	path string
}

// NewStore returns a Store backed by path.
func NewStore(path string) *Store { return &Store{path: path} }

// DefaultPath returns proxykeys.json under the aivault home (SPEC 4.4).
func DefaultPath(home string) string { return filepath.Join(home, "proxykeys.json") }

// Load reads all keys; a missing file yields an empty list.
func (s *Store) Load() ([]Key, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("proxykey: read: %w", err)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("proxykey: parse %s: %w", s.path, err)
	}
	return f.ProxyKeys, nil
}

// List returns all keys (including revoked; callers filter for display).
func (s *Store) List() ([]Key, error) { return s.Load() }

// Lookup returns the key whose SHA-256 matches plaintext, comparing in
// constant time over every stored digest (SPEC 4.4, 8.5). A missing or
// non-matching key yields (nil, nil).
func (s *Store) Lookup(plaintext string) (*Key, error) {
	keys, err := s.Load()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(plaintext))
	var found *Key
	for i := range keys {
		stored, err := hex.DecodeString(keys[i].SHA256)
		if err != nil {
			continue
		}
		// Compare against every digest so a match does not short-circuit early.
		if subtle.ConstantTimeCompare(sum[:], stored) == 1 {
			found = &keys[i]
		}
	}
	return found, nil
}

// Add stores a newly generated key; names must be unique (SPEC 4.4).
func (s *Store) Add(k *Key) error {
	keys, err := s.Load()
	if err != nil {
		return err
	}
	for _, e := range keys {
		if e.Name == k.Name {
			return fmt.Errorf("proxykey: name %q already exists", k.Name)
		}
		if e.ID == k.ID {
			return fmt.Errorf("proxykey: id %q already exists", k.ID)
		}
	}
	f := file{Version: fileVersion, ProxyKeys: append(keys, *k)}
	return s.save(&f)
}

// Revoke marks the key with the given ID or name revoked and returns the
// record updated (SPEC 4.4).
func (s *Store) Revoke(idOrName string) (*Key, error) {
	keys, err := s.Load()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].ID == idOrName || keys[i].Name == idOrName {
			keys[i].Revoked = true
			if err := s.save(&file{Version: fileVersion, ProxyKeys: keys}); err != nil {
				return nil, err
			}
			k := keys[i]
			return &k, nil
		}
	}
	return nil, fmt.Errorf("proxykey: no key with id or name %q", idOrName)
}

func (s *Store) save(f *file) error {
	if f.Version == 0 {
		f.Version = fileVersion
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("proxykey: encode: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(s.path, data, 0o600)
}

// writeFileAtomic writes data to path via an O_EXCL tmp file + rename
// (SPEC 8.2), mirroring the vault store.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("proxykey: stale tmp: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("proxykey: create tmp: %w", err)
	}
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("proxykey: write tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("proxykey: close tmp: %w", err)
	}
	return os.Rename(tmp, path)
}
