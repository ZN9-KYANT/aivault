// Package kdf derives the 32-byte master KEK from the master passphrase via
// Argon2id and manages the config.toml verifier blob (SPEC 4.1).
package kdf

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrWrongPassphrase is returned when the verifier blob fails to unwrap
	// under the derived KEK (SPEC 4.1).
	ErrWrongPassphrase = errors.New("wrong passphrase")

	// ErrWeakPassphrase is returned when the passphrase fails the policy
	// (SPEC 4.1: min 12 chars, zxcvhn strength >= 3).
	ErrWeakPassphrase = errors.New("weak passphrase")
)

// KEKSize is the master KEK size in bytes (SPEC 4.1).
const KEKSize = 32

// Passphrase policy (SPEC 4.1).
const (
	MinPassphraseLen   = 12
	MinPassphraseScore = 3
)

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

// DeriveKEK derives the 32-byte master KEK from the master passphrase via
// Argon2id (SPEC 4.1).
func DeriveKEK(passphrase []byte, p *Params) ([]byte, error) {
	if p == nil {
		return nil, errors.New("kdf: nil params")
	}
	if p.MemoryMiB == 0 || p.Time == 0 || p.Threads == 0 || p.Threads > 255 {
		return nil, fmt.Errorf("kdf: invalid argon2id parameters (m=%d, t=%d, p=%d)", p.MemoryMiB, p.Time, p.Threads)
	}
	salt, err := p.Salt()
	if err != nil {
		return nil, fmt.Errorf("kdf: salt: %w", err)
	}
	if len(salt) != 16 {
		return nil, fmt.Errorf("kdf: salt must be 16 bytes, got %d", len(salt))
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryMiB*1024, uint8(p.Threads), KEKSize), nil
}

// WrapVerifier returns a random verifier blob AEAD-wrapped (XChaCha20-Poly1305)
// under kek. The blob is stored in config.toml so unlock can confirm the
// passphrase in constant time without decrypting any vault file (SPEC 4.1).
func WrapVerifier(kek []byte) (blob []byte, err error) {
	aead, err := newVerifierAEAD(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kdf: nonce: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("kdf: verifier secret: %w", err)
	}
	defer Zeroize(secret)
	ct := aead.Seal(nil, nonce, secret, nil)
	blob = make([]byte, 0, len(nonce)+len(ct))
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return blob, nil
}

// UnwrapVerifier unwraps the verifier blob under kek; a failure means the
// passphrase is wrong (SPEC 4.1).
func UnwrapVerifier(kek, blob []byte) error {
	aead, err := newVerifierAEAD(kek)
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	if len(blob) < ns+aead.Overhead() {
		return fmt.Errorf("%w: verifier blob too short", ErrWrongPassphrase)
	}
	if _, err := aead.Open(nil, blob[:ns], blob[ns:], nil); err != nil {
		return ErrWrongPassphrase
	}
	return nil
}

func newVerifierAEAD(kek []byte) (cipher.AEAD, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("kdf: KEK must be %d bytes, got %d", KEKSize, len(kek))
	}
	return chacha20poly1305.NewX(kek)
}

// ValidatePassphrase enforces the master passphrase policy (SPEC 4.1).
func ValidatePassphrase(pw string) error {
	if len(pw) < MinPassphraseLen {
		return fmt.Errorf("%w: minimum %d characters", ErrWeakPassphrase, MinPassphraseLen)
	}
	if s := zxcvbn.PasswordStrength(pw, nil).Score; s < MinPassphraseScore {
		return fmt.Errorf("%w: strength %d/4, need >= %d", ErrWeakPassphrase, s, MinPassphraseScore)
	}
	return nil
}

// Zeroize best-effort clears b (SPEC 8.3). Callers must not reuse b afterward.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
