package kdf

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const testPassphrase = "zephyr-quartz-muffin-tundra-9"

func TestDeriveKEK(t *testing.T) {
	params, err := NewParams()
	if err != nil {
		t.Fatal(err)
	}
	kek1, err := DeriveKEK([]byte(testPassphrase), params)
	if err != nil {
		t.Fatal(err)
	}
	if len(kek1) != KEKSize {
		t.Fatalf("KEK size = %d, want %d", len(kek1), KEKSize)
	}
	kek2, err := DeriveKEK([]byte(testPassphrase), params)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kek1, kek2) {
		t.Error("KEK derivation not deterministic")
	}
	kek3, err := DeriveKEK([]byte("another-passphrase-123"), params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(kek1, kek3) {
		t.Error("different passphrases produced the same KEK")
	}
	params2, err := NewParams()
	if err != nil {
		t.Fatal(err)
	}
	kek4, err := DeriveKEK([]byte(testPassphrase), params2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(kek1, kek4) {
		t.Error("different salts produced the same KEK")
	}
}

func TestDeriveKEKBadParams(t *testing.T) {
	pass := []byte(testPassphrase)
	if _, err := DeriveKEK(pass, &Params{}); err == nil {
		t.Error("empty params should fail")
	}
	if _, err := DeriveKEK(pass, nil); err == nil {
		t.Error("nil params should fail")
	}
	p, err := NewParams()
	if err != nil {
		t.Fatal(err)
	}
	p.SaltHex = "abcd" // decodes to 2 bytes
	if _, err := DeriveKEK(pass, p); err == nil {
		t.Error("short salt should fail")
	}
	p2, err := NewParams()
	if err != nil {
		t.Fatal(err)
	}
	p2.SaltHex = "zz" // invalid hex
	if _, err := DeriveKEK(pass, p2); err == nil {
		t.Error("invalid hex salt should fail")
	}
}

func TestVerifierWrapUnwrap(t *testing.T) {
	params, err := NewParams()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := DeriveKEK([]byte(testPassphrase), params)
	if err != nil {
		t.Fatal(err)
	}
	defer Zeroize(kek)

	blob, err := WrapVerifier(kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := UnwrapVerifier(kek, blob); err != nil {
		t.Fatalf("unwrap with correct KEK: %v", err)
	}

	wrongKEK, err := DeriveKEK([]byte("wrong-passphrase-xyz-1"), params)
	if err != nil {
		t.Fatal(err)
	}
	defer Zeroize(wrongKEK)
	if err := UnwrapVerifier(wrongKEK, blob); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("unwrap with wrong KEK: err = %v, want ErrWrongPassphrase", err)
	}

	blob[len(blob)-1] ^= 0xff // corrupt the AEAD tag
	if err := UnwrapVerifier(kek, blob); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("unwrap with corrupt blob: err = %v, want ErrWrongPassphrase", err)
	}
}

func TestWrapVerifierBadKEK(t *testing.T) {
	if _, err := WrapVerifier(make([]byte, KEKSize-1)); err == nil {
		t.Error("short KEK should fail")
	}
	if err := UnwrapVerifier(make([]byte, KEKSize), []byte{1, 2, 3}); err == nil {
		t.Error("short blob should fail")
	}
}

func TestValidatePassphrase(t *testing.T) {
	if err := ValidatePassphrase("short"); !errors.Is(err, ErrWeakPassphrase) {
		t.Errorf("short passphrase: err = %v, want ErrWeakPassphrase", err)
	}
	if err := ValidatePassphrase("password12345"); !errors.Is(err, ErrWeakPassphrase) {
		t.Errorf("weak passphrase: err = %v, want ErrWeakPassphrase", err)
	}
	if err := ValidatePassphrase(testPassphrase); err != nil {
		t.Errorf("strong passphrase failed: %v", err)
	}
}

func TestZeroize(t *testing.T) {
	b := []byte(strings.Repeat("s", 32))
	Zeroize(b)
	if string(b) != strings.Repeat("\x00", 32) {
		t.Error("Zeroize did not clear the buffer")
	}
}
