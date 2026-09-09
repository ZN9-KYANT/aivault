package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newArchiveHome builds a home with config, meta, two vault files and a
// proxykeys.json stub — everything the backup should capture.
func newArchiveHome(t *testing.T) (home, pass string) {
	t.Helper()
	home = t.TempDir()
	pass = "zephyr-quartz-muffin-tundra-9"
	if err := os.MkdirAll(filepath.Join(home, "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	st := NewStore(home)
	for _, id := range []string{"openai", "deepseek"} {
		if err := st.Save(id, []byte(pass), &Payload{
			Version: PayloadVersion, Provider: id, Kind: KindAPIKey,
			APIKey: &APIKey{Key: "sk-" + id + "-secret", BaseURL: "https://" + id + ".example/v1"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	meta, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	meta.Providers["openai"] = ProviderMeta{Kind: string(KindAPIKey), BaseURL: "https://x", Enabled: true}
	if err := st.SaveMeta(meta); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "proxykeys.json"), []byte(`{"version":1,"proxy_keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, pass
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	home, pass := newArchiveHome(t)
	out := filepath.Join(t.TempDir(), "backup.age")

	if err := Backup(home, out, []byte(pass)); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() < 100 {
		t.Fatalf("backup file missing or tiny: %v", err)
	}
	// The archive must not be plaintext.
	head, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(head), "age-encryption.org/v1") {
		t.Fatalf("archive is not age-encrypted")
	}

	// Restore into a fresh home.
	dst := t.TempDir()
	restored, err := RestoreArchive(dst, out, []byte(pass), false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(restored) < 4 {
		t.Fatalf("restored %d files, want >= 4 (config, meta, vault files, proxykeys)", len(restored))
	}
	orig, _ := os.ReadFile(filepath.Join(home, "vault", "openai.json.age"))
	got, err := os.ReadFile(filepath.Join(dst, "vault", "openai.json.age"))
	if err != nil {
		t.Fatalf("restored vault file missing: %v", err)
	}
	if string(orig) != string(got) {
		t.Fatal("restored vault payload differs from the original")
	}

	// Refuse to clobber without --force.
	if _, err := RestoreArchive(dst, out, []byte(pass), false); err == nil {
		t.Fatal("restore without --force over an existing vault must fail")
	}
	if _, err := RestoreArchive(dst, out, []byte(pass), true); err != nil {
		t.Fatalf("restore --force: %v", err)
	}

	// Wrong passphrase.
	dst2 := t.TempDir()
	if _, err := RestoreArchive(dst2, out, []byte("wrong-wrong-wrong-1"), false); err == nil {
		t.Fatal("restore with wrong passphrase must fail")
	}
}