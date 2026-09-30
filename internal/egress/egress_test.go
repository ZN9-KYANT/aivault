package egress

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reset(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { _ = SetAllowlist(nil) })
}

func dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return Guarded(d.DialContext)
}

func TestEgressBlocksUnlistedHost(t *testing.T) {
	reset(t)
	if err := SetAllowlist([]string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	guarded := dialer()
	_, err := guarded(context.Background(), "tcp", srv.Listener.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "non-allowlisted") {
		t.Fatalf("expected block for unlisted host, got err=%v", err)
	}
}

func TestEgressAllowsListedHost(t *testing.T) {
	reset(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = r }))
	defer srv.Close()
	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetAllowlist([]string{strings.ToUpper(host)}); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{DialContext: dialer()}, Timeout: 5 * time.Second}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("allowlisted host must pass: %v", err)
	}
	resp.Body.Close()
}

func TestEgressFollowsRedirectAndRevalidates(t *testing.T) {
	reset(t)
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = r }))
	defer final.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to the same server via a DIFFERENT dial hostname
		// (localhost instead of 127.0.0.1) — the blocked one.
		http.Redirect(w, r, strings.Replace(final.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
	}))
	defer redir.Close()

	if err := SetAllowlist([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{DialContext: dialer()}, Timeout: 5 * time.Second}
	_, err := c.Get(redir.URL + "/jump")
	if err == nil {
		t.Fatal("expected redirect to unlisted host to be refused")
	}
	if !strings.Contains(err.Error(), "non-allowlisted") && !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEgressDisabledByEmptyList(t *testing.T) {
	reset(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = r }))
	defer srv.Close()
	if err := SetAllowlist([]string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := SetAllowlist(nil); err != nil {
		t.Fatal(err)
	}
	if Enabled() {
		t.Fatal("guard must be disabled by an empty list")
	}
	c := &http.Client{Transport: &http.Transport{DialContext: dialer()}, Timeout: 5 * time.Second}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("disabled guard must pass through: %v", err)
	}
	resp.Body.Close()
}

func TestEgressRejectsEmptyHost(t *testing.T) {
	reset(t)
	if err := SetAllowlist([]string{"  "}); err == nil {
		t.Fatal("expected error for an empty allowlist host")
	}
	// State must remain unchanged (previous set) after a failed update.
	if err := SetAllowlist([]string{"ok.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := SetAllowlist([]string{" "}); err == nil {
		t.Fatal("expected error")
	}
	if !Enabled() || len(Hosts()) == 0 {
		t.Fatalf("failed update must keep previous list, got enabled=%v hosts=%v", Enabled(), Hosts())
	}
}
