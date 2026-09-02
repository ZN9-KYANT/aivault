// Package kdf derives the 32-byte master KEK from the master passphrase via
// Argon2id and manages the config.toml verifier blob (SPEC 4.1).
package kdf

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

// KEKSize is the master KEK size in bytes (SPEC 4.1).
const KEKSize = 32

// Params are the Argon2id parameters and salt persisted in config.toml (SPEC 4.1).
type Params struct {
	MemoryMiB uint32 `toml:"memory_mib"` // default 64
	Time      uint32 `toml:"time"`       // default 3
	Threads   uint32 `toml:"threads"`    // default 4
	SaltHex   string `toml:"salt_hex"`   // 16-byte random salt, hex-encoded
}

// Salt returns the decoded salt bytes.
func (p *Params) Salt() ([]byte, error) {
	return hex.DecodeString(p.SaltHex)
}

// NewParams returns the default Argon2id parameters with a fresh 16-byte salt.
func NewParams() (*Params, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &Params{
		MemoryMiB: 64,
		Time:      3,
		Threads:   4,
		SaltHex:   hex.EncodeToString(salt),
	}, nil
}

// DeriveKEK derives the 32-byte master KEK from the master passphrase
// (SPEC 4.1).
func DeriveKEK(passphrase []byte, p *Params) ([]byte, error) {
	return nil, errs.ErrNotImplemented // TODO: argon2.IDKey
}

// WrapVerifier returns a random verifier blob AEAD-wrapped under kek. The
// blob is stored in config.toml so unlock can confirm the passphrase in
// constant time without decrypting any vault file (SPEC 4.1).
func WrapVerifier(kek []byte) (blob []byte, err error) {
	return nil, errs.ErrNotImplemented
}

// UnwrapVerifier unwraps the verifier blob under kek. A failure means the
// passphrase is wrong (SPEC 4.1).
func UnwrapVerifier(kek, blob []byte) error {
	return errs.ErrNotImplemented
}