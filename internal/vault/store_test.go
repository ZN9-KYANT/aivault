package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const testPassphrase = "zephyr-quartz-muffin-tundra-9"

func TestSaveLoadRoundTrip(t *testing.T) {
	st := NewStore(t.TempDir())
	in := &Payload{
		Version:  PayloadVersion,
		Provider: "openai",
		Kind:     KindAPIKey,
		APIKey: &APIKey{
			Key:     "sk-test-1234567890abcdef",
			BaseURL: "https://api.openai.com/v1",
			Headers: map[string]string{"X-Test": "1"},
		},
	}
	if err := st.Save("openai", []byte(testPassphrase), in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := st.Load("openai", []byte(testPassphrase))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.APIKey == nil || out.APIKey.Key != in.APIKey.Key || out.APIKey.BaseURL != in.APIKey.BaseURL {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.APIKey.Headers["X-Test"] != "1" {
		t.Errorf("header round-trip mismatch: %+v", out.APIKey.Headers)
	}
	if out.Provider != "openai" || out.Kind != KindAPIKey || out.Version != PayloadVersion {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestLoadWrongPassphrase(t *testing.T) {
	st := NewStore(t.TempDir())
	in := &Payload{Version: 1, Provider: "openai", Kind: KindAPIKey, APIKey: &APIKey{Key: "sk-x", BaseURL: "u"}}
	if err := st.Save("openai", []byte(testPassphrase), in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := st.Load("openai", []byte("wrong-passphrase-xyz-1")); err == nil {
		t.Fatal("Load with wrong passphrase should fail")
	}
}

func TestLoadMissing(t *testing.T) {
	st := NewStore(t.TempDir())
	if _, err := st.Load("openai", []byte(testPassphrase)); err == nil {
		t.Fatal("Load of missing provider should fail")
	}
}

func TestSaveAtomicOverwrite(t *testing.T) {
	st := NewStore(t.TempDir())
	pass := []byte(testPassphrase)
	in := &Payload{Version: 1, Provider: "openai", Kind: KindAPIKey, APIKey: &APIKey{Key: "sk-first-12345", BaseURL: "u"}}
	if err := st.Save("openai", pass, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(st.dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 vault file after save, got %d", len(entries))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(st.ProviderPath("openai"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("vault file mode = %o, want 600", info.Mode().Perm())
		}
	}

	// Overwrite (rotation) replaces the payload atomically.
	in2 := &Payload{Version: 1, Provider: "openai", Kind: KindAPIKey, APIKey: &APIKey{Key: "sk-second-67890", BaseURL: "u"}}
	if err := st.Save("openai", pass, in2); err != nil {
		t.Fatalf("Save rotate: %v", err)
	}
	out, err := st.Load("openai", pass)
	if err != nil {
		t.Fatal(err)
	}
	if out.APIKey.Key != "sk-second-67890" {
		t.Errorf("rotated key = %q, want sk-second-67890", out.APIKey.Key)
	}
	entries, err = os.ReadDir(filepath.Join(st.dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("leftover tmp files: %d entries", len(entries))
	}
}

func TestMetaRoundTrip(t *testing.T) {
	st := NewStore(t.TempDir())
	m, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != PayloadVersion || m.Providers == nil {
		t.Fatalf("fresh meta = %+v", m)
	}
	m.Providers["openai"] = ProviderMeta{
		Kind:    "apikey",
		BaseURL: "https://api.openai.com/v1",
		KeyHint: "sk-...cdef",
		Enabled: true,
	}
	if err := st.SaveMeta(m); err != nil {
		t.Fatalf("SaveMeta: %v", err)
	}
	m2, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	pm, ok := m2.Providers["openai"]
	if !ok || pm.KeyHint != "sk-...cdef" || pm.Kind != "apikey" {
		t.Fatalf("meta round-trip mismatch: %+v", m2)
	}
}

func TestKeyHint(t *testing.T) {
	if got := KeyHint("sk-abc12345xyz9"); got != "sk-...xyz9" {
		t.Errorf("KeyHint = %q, want sk-...xyz9", got)
	}
	if got := KeyHint("short"); got != "..." {
		t.Errorf("KeyHint(short) = %q, want ...", got)
	}
}

func TestDefaultHome(t *testing.T) {
	home, err := DefaultHome()
	if err != nil {
		t.Fatal(err)
	}
	if home == "" {
		t.Error("DefaultHome is empty")
	}
}
