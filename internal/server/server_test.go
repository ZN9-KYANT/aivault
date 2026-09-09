package server

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/kdf"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

// newTestHome builds a vault home with two apikey providers (one enabled,
// one disabled), a credential-free custom provider, and a meta-only entry.
func newTestHome(t *testing.T) (home, pass string) {
	t.Helper()
	home = t.TempDir()
	pass = "zephyr-quartz-muffin-tundra-9"

	params, err := kdf.NewParams()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := kdf.DeriveKEK([]byte(pass), params)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := kdf.WrapVerifier(kek)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.KDF = *params
	cfg.Verifier = hex.EncodeToString(blob)
	if err := config.Save(config.Path(home), cfg); err != nil {
		t.Fatal(err)
	}

	st := vault.NewStore(home)
	mustSave := func(id string, p *vault.Payload) {
		t.Helper()
		if err := st.Save(id, []byte(pass), p); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	mustSave("openai", &vault.Payload{
		Version: vault.PayloadVersion, Provider: "openai", Kind: vault.KindAPIKey,
		APIKey: &vault.APIKey{Key: "sk-test-openai", BaseURL: "https://api.openai.com/v1"},
	})
	mustSave("deepseek", &vault.Payload{
		Version: vault.PayloadVersion, Provider: "deepseek", Kind: vault.KindAPIKey,
		APIKey: &vault.APIKey{Key: "sk-test-deepseek", BaseURL: "https://api.deepseek.com/v1"},
	})
	mustSave("myproxy", &vault.Payload{
		Version: vault.PayloadVersion, Provider: "myproxy", Kind: vault.KindNone,
		None: &vault.NoneCred{BaseURL: "http://127.0.0.1:1"},
	})

	meta, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entry := func(kind string, enabled bool) vault.ProviderMeta {
		return vault.ProviderMeta{Kind: kind, BaseURL: "https://x.example", Enabled: enabled, CreatedAt: now, UpdatedAt: now}
	}
	meta.Providers["openai"] = entry(string(vault.KindAPIKey), true)
	meta.Providers["deepseek"] = entry(string(vault.KindAPIKey), false) // disabled — unlock must skip
	meta.Providers["myproxy"] = entry(string(vault.KindNone), true)     // credential-free
	// A meta-only entry with no vault file must not break unlock.
	meta.Providers["ghost"] = entry(string(vault.KindAPIKey), true)
	if err := st.SaveMeta(meta); err != nil {
		t.Fatal(err)
	}
	return home, pass
}

// startTestServer listens and serves the admin plane in the background.
func startTestServer(t *testing.T, home string) (*Server, *Client) {
	t.Helper()
	if !unixSocketsWork(t) {
		t.Skip("AF_UNIX not available in this environment")
	}
	s := New(Options{
		Home:         home,
		ConfigPath:   config.Path(home),
		SocketPath:   SocketPath(home),
		AutoLockMins: 15,
	})
	ln, err := s.listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.httpSrv = &http.Server{Handler: s.adminRoutes()}
	go func() { _ = s.httpSrv.Serve(ln) }()
	t.Cleanup(func() { s.shutdown("test") })
	return s, NewClient(SocketPath(home))
}

// unixSocketsWork probes AF_UNIX availability (e.g. old Windows builds).
func unixSocketsWork(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	p := dir + "/probe.sock"
	ln, err := net.Listen("unix", p)
	if err != nil {
		return false
	}
	_ = ln.Close()
	_ = os.Remove(p)
	return true
}

func TestAdminLifecycle(t *testing.T) {
	home, pass := newTestHome(t)
	s, c := startTestServer(t, home)

	// Locked initially.
	st, err := c.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Locked || st.Providers != 0 || st.AutoLockMinutes != 15 {
		t.Fatalf("initial status = %+v, want locked/0/15", st)
	}

	// Wrong passphrase: rejected, still locked, audited.
	if _, err := c.Unlock([]byte("wrong-wrong-wrong-1")); err == nil {
		t.Fatal("unlock with wrong passphrase must fail")
	}
	if st, _ := c.Status(); !st.Locked {
		t.Fatal("keyring must stay locked after failed unlock")
	}

	// Correct passphrase: enabled apikey providers only (openai; deepseek is
	// disabled, myproxy is none-kind, "ghost" has no vault file).
	st, err = c.Unlock([]byte(pass))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if st.Locked || st.Providers != 1 || len(st.ProviderIDs) != 1 || st.ProviderIDs[0] != "openai" {
		t.Fatalf("status after unlock = %+v, want unlocked with [openai]", st)
	}
	if p, ok := s.ring.Get("openai"); !ok || p.APIKey.Key != "sk-test-openai" {
		t.Fatalf("keyring payload = %+v", p)
	}

	// Re-unlock with a wrong passphrase must keep the old keyring.
	if err := os.WriteFile(config.Path(home), []byte("garbage-not-toml"), 0o600); err == nil {
		// Corrupt the config so unlock's config reload fails; the keyring
		// must stay as-is.
		if _, err := c.Unlock([]byte(pass)); err == nil {
			t.Fatal("unlock with broken config must fail")
		}
		if st, _ := c.Status(); st.Locked || st.Providers != 1 {
			t.Fatalf("failed re-unlock must preserve keyring, got %+v", st)
		}
	} else {
		t.Fatalf("corrupt config: %v", err)
	}

	// Restore the config, then lock.
	if err := config.Save(config.Path(home), func() *config.Config {
		cfg := config.Default()
		cfg.AutoLockMins = 15
		return cfg
	}()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if st, _ := c.Status(); !st.Locked {
		t.Fatal("keyring must be locked after lock")
	}
	// Idempotent lock.
	if _, err := c.Lock(); err != nil {
		t.Fatalf("second lock: %v", err)
	}

	// Audit trail: unlock ok, auth.fail, lock manual.
	entries, err := audit.Tail(home+"/audit.log", 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, e := range entries {
		got[e.Event+"/"+e.Outcome]++
	}
	if got["unlock/ok"] == 0 || got["auth.fail/wrong-passphrase"] == 0 || got["lock/manual"] == 0 {
		t.Fatalf("audit entries missing: %v", got)
	}
}

func TestUnlockDecryptFailureKeepsKeyring(t *testing.T) {
	home, pass := newTestHome(t)
	s, c := startTestServer(t, home)

	if _, err := c.Unlock([]byte(pass)); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Corrupt the stored credential: re-encrypt under a different passphrase.
	st := vault.NewStore(home)
	if err := st.Save("openai", []byte("other-pass-other-1"), &vault.Payload{
		Version: vault.PayloadVersion, Provider: "openai", Kind: vault.KindAPIKey,
		APIKey: &vault.APIKey{Key: "sk-garbage", BaseURL: "https://api.openai.com/v1"},
	}); err != nil {
		t.Fatal(err)
	}

	// The verifier still accepts the master passphrase, but decryption
	// fails — the old keyring must survive untouched (SPEC 4.2).
	if _, err := c.Unlock([]byte(pass)); err == nil {
		t.Fatal("unlock over a corrupt vault file must fail")
	}
	if s.ring.Unlocked() != true {
		t.Fatal("keyring must remain unlocked after failed re-unlock")
	}
	if p, ok := s.ring.Get("openai"); !ok || p == nil || p.APIKey == nil || p.APIKey.Key != "sk-test-openai" {
		t.Fatalf("old keyring contents must survive a failed re-unlock (ok=%v p=%+v)", ok, p)
	}
}

func TestSweepIdle(t *testing.T) {
	home, pass := newTestHome(t)
	s, _ := startTestServer(t, home)

	if _, err := s.unlock([]byte(pass)); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Fresh activity: no lock.
	s.mu.Lock()
	s.lastActive = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	if s.sweepIdle(time.Now()) {
		t.Fatal("sweep locked before the idle timeout")
	}

	// Past the 15-minute timeout: lock.
	s.mu.Lock()
	s.lastActive = time.Now().Add(-16 * time.Minute)
	s.mu.Unlock()
	if !s.sweepIdle(time.Now()) {
		t.Fatal("sweep did not lock after the idle timeout")
	}
	if s.ring.Unlocked() {
		t.Fatal("keyring must be locked after idle sweep")
	}

	// Disabled timeout never locks.
	s2 := New(Options{Home: home, SocketPath: SocketPath(home), AutoLockMins: 0})
	if s2.sweepIdle(time.Now()) {
		t.Fatal("sweep locked with auto-lock disabled")
	}
}

func TestListenStaleAndLiveSocket(t *testing.T) {
	if !unixSocketsWork(t) {
		t.Skip("AF_UNIX not available in this environment")
	}
	home, _ := newTestHome(t)
	sock := SocketPath(home)
	s := New(Options{Home: home, ConfigPath: config.Path(home), SocketPath: sock})

	// Garbage file where the socket should be: stale, must be removed.
	if err := os.WriteFile(sock, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := s.listen()
	if err != nil {
		t.Fatalf("listen with stale socket: %v", err)
	}
	defer ln.Close()

	// A second listen against the live socket must refuse to start.
	s2 := New(Options{Home: home, SocketPath: sock})
	_, err = s2.listen()
	if err == nil {
		t.Fatal("listen on a live socket must fail")
	}
	if !strings.Contains(err.Error(), "already served") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShutdownRemovesSocketAndLocks(t *testing.T) {
	if !unixSocketsWork(t) {
		t.Skip("AF_UNIX not available in this environment")
	}
	home, pass := newTestHome(t)
	s, _ := startTestServer(t, home)
	if _, err := s.unlock([]byte(pass)); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	s.shutdown("shutdown")
	if _, err := os.Stat(SocketPath(home)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socket must be removed on shutdown, got %v", err)
	}
	if s.ring.Unlocked() {
		t.Fatal("keyring must be zeroized on shutdown")
	}
	entries, err := audit.Tail(home+"/audit.log", 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawShutdown bool
	for _, e := range entries {
		if e.Event == audit.EventLock && e.Outcome == "shutdown" {
			sawShutdown = true
		}
	}
	if !sawShutdown {
		t.Fatalf("shutdown must audit its reason, got %+v", entries)
	}
}

func TestAuditEndpoint(t *testing.T) {
	home, pass := newTestHome(t)
	_, c := startTestServer(t, home)
	if _, err := c.Unlock([]byte(pass)); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	entries, err := c.AuditTail(10)
	if err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry (unlock/ok)")
	}
	last := entries[len(entries)-1]
	if last.Event != audit.EventUnlock || last.Outcome != "ok" {
		t.Fatalf("last entry = %+v, want unlock/ok", last)
	}
}