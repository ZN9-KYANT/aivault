package config

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ZN9-KYANT/aivault/internal/kdf"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	cfg := Default()
	cfg.Server.Port = 9999
	cfg.AutoLockMins = 30
	cfg.KDF.MemoryMiB = 64
	cfg.KDF.Time = 3
	cfg.KDF.Threads = 4
	cfg.KDF.SaltHex = "deadbeef"
	cfg.Verifier = "cafebabe"

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Server.Port != 9999 {
		t.Errorf("port = %d, want 9999", got.Server.Port)
	}
	if got.AutoLockMins != 30 {
		t.Errorf("auto_lock_minutes = %d, want 30", got.AutoLockMins)
	}
	if got.KDF.SaltHex != "deadbeef" {
		t.Errorf("salt = %q, want deadbeef", got.KDF.SaltHex)
	}
	if got.Verifier != "cafebabe" {
		t.Errorf("verifier = %q, want cafebabe", got.Verifier)
	}
}

func TestVerifyPassphrase(t *testing.T) {
	params, err := kdf.NewParams()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("zephyr-quartz-muffin-tundra-9")
	kek, err := kdf.DeriveKEK(pass, params)
	if err != nil {
		t.Fatal(err)
	}
	defer kdf.Zeroize(kek)
	blob, err := kdf.WrapVerifier(kek)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Default()
	cfg.KDF = *params
	cfg.Verifier = hex.EncodeToString(blob)

	if err := cfg.VerifyPassphrase(pass); err != nil {
		t.Errorf("correct passphrase rejected: %v", err)
	}
	err = cfg.VerifyPassphrase([]byte("wrong-passphrase-xyz-1"))
	if !errors.Is(err, kdf.ErrWrongPassphrase) {
		t.Errorf("wrong passphrase err = %v, want ErrWrongPassphrase", err)
	}
	if err := Default().VerifyPassphrase(pass); err == nil {
		t.Error("uninitialized config should fail verification")
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := Save(path, Default()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Server.Port != 8317 {
		t.Errorf("port = %d, want 8317", got.Server.Port)
	}
	if got.AutoLockMins != 15 {
		t.Errorf("auto_lock_minutes = %d, want 15", got.AutoLockMins)
	}
}
