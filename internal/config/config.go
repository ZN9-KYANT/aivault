// Package config loads and saves ~/.aivault/config.toml (SPEC 3.1, 4.1, 4.3).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/ZN9-KYANT/aivault/internal/kdf"
)

// Server configures the data-plane HTTP listener (SPEC 6.1).
type Server struct {
	Port int `toml:"port"`
}

// Admin configures the optional TCP admin plane (SPEC 4.3).
type Admin struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"` // e.g. 127.0.0.1:8318
	Token   string `toml:"token"`  // hex-encoded random 32 bytes; never printed after init
}

// Spend configures per-token cost estimation for proxy-key spend caps
// (SPEC 8.8): USD per 1M tokens, with an optional per-model-prefix table.
type Spend struct {
	InputUSDPer1M  float64      `toml:"input_usd_per_1m"`
	OutputUSDPer1M float64      `toml:"output_usd_per_1m"`
	ModelPrices    []ModelPrice `toml:"model_prices"`
}

// ModelPrice overrides the default estimate for models whose namespaced
// name starts with Prefix; the first match wins.
type ModelPrice struct {
	Prefix         string  `toml:"prefix"`
	InputUSDPer1M  float64 `toml:"input_usd_per_1m"`
	OutputUSDPer1M float64 `toml:"output_usd_per_1m"`
}

// Config mirrors config.toml.
type Config struct {
	Server       Server     `toml:"server"`
	AutoLockMins int        `toml:"auto_lock_minutes"`
	Failover     bool       `toml:"failover"` // retry next alias chain entry on 429/5xx/timeout (SPEC 6.1, default off)
	Spend        Spend      `toml:"spend"`
	KDF          kdf.Params `toml:"kdf"`
	Verifier     string     `toml:"verifier"` // hex-encoded KEK-wrapped verifier blob (SPEC 4.1)
	Admin        Admin      `toml:"admin"`
}

// Default returns the default configuration (SPEC 4.2: 15-minute auto-lock;
// SPEC 6.1: port 8317).
func Default() *Config {
	return &Config{
		Server:       Server{Port: 8317},
		AutoLockMins: 15,
		Spend:        Spend{InputUSDPer1M: 0.5, OutputUSDPer1M: 1.5}, // rough cross-provider default estimate
	}
}

// Path returns the config.toml path under the aivault home dir.
func Path(dir string) string { return filepath.Join(dir, "config.toml") }

// Load reads config.toml, keeping defaults for absent fields.
func Load(path string) (*Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := toml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// VerifyPassphrase confirms the master passphrase against the config.toml
// verifier blob without decrypting any vault file (SPEC 4.1).
func (c *Config) VerifyPassphrase(passphrase []byte) error {
	if c.Verifier == "" {
		return errors.New("config: vault not initialized (verifier missing)")
	}
	blob, err := hex.DecodeString(c.Verifier)
	if err != nil {
		return fmt.Errorf("config: verifier: %w", err)
	}
	kek, err := kdf.DeriveKEK(passphrase, &c.KDF)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	defer kdf.Zeroize(kek)
	return kdf.UnwrapVerifier(kek, blob)
}

// Save atomically writes config.toml with 0600 permissions (SPEC 8.2).
// Note: Unix mode bits are advisory-only on Windows.
func Save(path string, cfg *Config) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := toml.NewEncoder(f).Encode(cfg); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
