package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultProviders(t *testing.T) {
	home := t.TempDir()

	// Missing vault dir yields no IDs.
	ids, err := vaultProviders(home)
	if err != nil {
		t.Fatalf("missing vault dir: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("want no ids, got %v", ids)
	}

	vdir := filepath.Join(home, "vault")
	if err := os.MkdirAll(vdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zebra.json.age", "alpha.json.age", "ignore.txt", "stale.json.age.tmp"} {
		if err := os.WriteFile(filepath.Join(vdir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A directory whose name matches the payload suffix must be skipped.
	if err := os.Mkdir(filepath.Join(vdir, "subdir.json.age"), 0o700); err != nil {
		t.Fatal(err)
	}

	ids, err = vaultProviders(home)
	if err != nil {
		t.Fatalf("vault dir: %v", err)
	}
	want := []string{"alpha", "zebra"}
	if len(ids) != len(want) {
		t.Fatalf("want %v, got %v", want, ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("want %v, got %v", want, ids)
		}
	}
}
