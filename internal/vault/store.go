package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// age scrypt work factor bounds (SPEC 4.1: per-file random, >= log2(18)).
const (
	minScryptWorkFactor = 18
	maxScryptWorkFactor = 20
)

// Store reads and writes the on-disk vault under ~/.aivault (SPEC 3.1):
// vault/<provider>.json.age plus meta.json. All writes are atomic
// (O_EXCL tmp file + rename, SPEC 8.2).
type Store struct {
	dir string // ~/.aivault
}

// NewStore returns a Store rooted at dir (e.g. ~/.aivault).
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// DefaultHome returns the aivault home directory ~/.aivault (SPEC 3.1).
func DefaultHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("vault: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aivault"), nil
}

// ProviderPath returns vault/<provider>.json.age for a provider file.
func (s *Store) ProviderPath(provider string) string {
	return filepath.Join(s.dir, "vault", provider+".json.age")
}

// Save atomically encrypts p to vault/<provider>.json.age using the master
// passphrase via an age scrypt recipient (SPEC 3.2, 8.2).
func (s *Store) Save(provider string, passphrase []byte, p *Payload) error {
	if len(passphrase) == 0 {
		return errors.New("vault: empty passphrase")
	}
	if p == nil {
		return errors.New("vault: nil payload")
	}

	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return fmt.Errorf("vault: encode payload: %w", err)
	}

	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(maxScryptWorkFactor-minScryptWorkFactor+1))
	if err != nil {
		return fmt.Errorf("vault: work factor: %w", err)
	}
	recipient.SetWorkFactor(minScryptWorkFactor + int(nBig.Int64()))

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	if _, err := w.Write(plain.Bytes()); err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("vault: seal: %w", err)
	}

	path := s.ProviderPath(provider)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return writeFileAtomic(path, ciphertext.Bytes(), 0o600)
}

// Load decrypts and parses vault/<provider>.json.age with the master
// passphrase (age scrypt recipient, SPEC 3.2).
func (s *Store) Load(provider string, passphrase []byte) (*Payload, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("vault: empty passphrase")
	}
	path := s.ProviderPath(provider)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("vault: no credential stored for %q", provider)
		}
		return nil, err
	}
	defer f.Close()

	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	r, err := age.Decrypt(f, identity)
	if err != nil {
		// Wrong passphrase or corrupted file. Passphrase is normally confirmed
		// against the config.toml verifier first (SPEC 4.1), so treat as damage.
		return nil, fmt.Errorf("vault: decrypt %s: %w", provider, err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", provider, err)
	}
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("vault: parse %s: %w", provider, err)
	}
	return &p, nil
}

func (s *Store) metaPath() string {
	return filepath.Join(s.dir, "meta.json")
}

// LoadMeta reads the plaintext index meta.json (SPEC 3.3). A missing file
// yields an empty meta — the CLI can list without unlocking.
func (s *Store) LoadMeta() (*Meta, error) {
	data, err := os.ReadFile(s.metaPath())
	if errors.Is(err, fs.ErrNotExist) {
		return &Meta{Version: PayloadVersion, Providers: make(map[string]ProviderMeta)}, nil
	}
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("vault: parse meta.json: %w", err)
	}
	if m.Providers == nil {
		m.Providers = make(map[string]ProviderMeta)
	}
	if m.Version == 0 {
		m.Version = PayloadVersion
	}
	return &m, nil
}

// SaveMeta atomically writes meta.json (SPEC 3.3, 8.2).
func (s *Store) SaveMeta(m *Meta) error {
	if m.Version == 0 {
		m.Version = PayloadVersion
	}
	if m.Providers == nil {
		m.Providers = make(map[string]ProviderMeta)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: encode meta: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(s.metaPath(), data, 0o600)
}

// KeyHint returns the safe display hint for a secret: first-3/last-4
// characters only (SPEC 3.3).
func KeyHint(key string) string {
	if len(key) < 8 {
		return "..."
	}
	return key[:3] + "..." + key[len(key)-4:]
}

// writeFileAtomic writes data to path via an O_EXCL tmp file + rename
// (SPEC 8.2). A stale tmp file from a crashed writer is removed first.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: stale tmp: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("vault: create tmp: %w", err)
	}
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("vault: write tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vault: close tmp: %w", err)
	}
	return os.Rename(tmp, path)
}
