//go:build unix

package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPermsAcceptsOwnerOnly(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	vDir := filepath.Join(home, "vault")
	if err := os.Mkdir(vDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vDir, "openai.json.age"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPerms(home); err != nil {
		t.Fatalf("owner-only layout must pass: %v", err)
	}
}

func TestCheckPermsRejectsOpenFiles(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "meta.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckPerms(home)
	if err == nil {
		t.Fatal("expected rejection for open home/meta perms")
	}
	if !strings.Contains(err.Error(), "meta.json") {
		t.Fatalf("error must name the offending file: %v", err)
	}
}
