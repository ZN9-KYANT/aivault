package vault

import (
	"path/filepath"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

// Store reads and writes the on-disk vault under ~/.aivault (SPEC 3.1):
// vault/<provider>.json.age plus meta.json. All writes are atomic
// (tmp file + rename, SPEC 8.2).
type Store struct {
	dir string // ~/.aivault
}

// NewStore returns a Store rooted at dir (e.g. ~/.aivault).
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// ProviderPath returns vault/<provider>.json.age for a provider file.
func (s *Store) ProviderPath(provider string) string {
	return filepath.Join(s.dir, "vault", provider+".json.age")
}

// Load decrypts and parses vault/<provider>.json.age with the master
// passphrase (age scrypt recipient, SPEC 3.2, 4.1).
func (s *Store) Load(provider string, passphrase []byte) (*Payload, error) {
	return nil, errs.ErrNotImplemented // TODO: age scrypt decrypt round-trip
}

// Save atomically encrypts p to vault/<provider>.json.age (tmp + rename, SPEC 8.2).
func (s *Store) Save(provider string, passphrase []byte, p *Payload) error {
	return errs.ErrNotImplemented
}

// LoadMeta reads the plaintext index meta.json (SPEC 3.3).
func (s *Store) LoadMeta() (*Meta, error) {
	return nil, errs.ErrNotImplemented
}

// SaveMeta atomically writes meta.json.
func (s *Store) SaveMeta(m *Meta) error {
	return errs.ErrNotImplemented
}