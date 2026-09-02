// Package proxykey issues and verifies downstream client keys (SPEC 4.4):
// returned once as vk-<48 hex>, stored only as SHA-256 hashes in
// proxykeys.json, and compared in constant time.
package proxykey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

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

// Store persists proxy keys to proxykeys.json (SPEC 4.4).
type Store struct {
	path string
}

// NewStore returns a Store backed by path.
func NewStore(path string) *Store { return &Store{path: path} }

// List returns all keys (stub).
func (s *Store) List() ([]Key, error) { return nil, errs.ErrNotImplemented }

// Add stores a newly generated key (stub).
func (s *Store) Add(k *Key) error { return errs.ErrNotImplemented }

// Revoke marks the key with the given ID revoked (stub).
func (s *Store) Revoke(id string) error { return errs.ErrNotImplemented }