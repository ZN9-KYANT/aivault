// Package config loads and saves ~/.aivault/config.toml (SPEC 3.1, 4.1, 4.3).
package config

import (
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

// Config mirrors config.toml.
type Config struct {
	Server       Server     `toml:"server"`
	AutoLockMins  int        `toml:"auto_lock_minutes"`
	KDF           kdf.Params `toml:"kdf"`
	Verifier      string     `toml:"verifier"` // hex-encoded KEK-wrapped verifier blob (SPEC 4.1)
	Admin         Admin      `toml:"admin"`
}

// Default returns the default configuration (SPEC 4.2: 15-minute auto-lock;
// SPEC 6.1: port 8317).
func Default() *Config {
	return &Config{
		Server:       Server{Port: 8317},
		AutoLockMins: 15,
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