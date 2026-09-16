package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ZN9-KYANT/aivault/internal/redact"
)

// probeUpstreamError must surface the upstream body (diagnosability) while
// scrubbing the credential (SPEC 8.4) — including key shapes the pattern list
// does not know, via redact.Register of the literal credential.
func TestProbeSurfacesRedactedUpstreamError(t *testing.T) {
	redact.Reset()
	defer redact.Reset()
	secret := "thk_live_AAAA2222BBBB4444CCCC6666DDDD8888EEEE"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":{"message":"key %s is forbidden: no models scope","code":"forbidden"}}`, secret)
	}))
	defer srv.Close()

	pc := newProviderClient()
	_, _, err := pc.probe(srv.URL, secret)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "HTTP 403") || !strings.Contains(msg, "no models scope") {
		t.Fatalf("expected status + body snippet in error, got %q", msg)
	}
	if strings.Contains(msg, secret) {
		t.Fatalf("credential leaked in probe error: %q", msg)
	}
}

// Empty upstream body still yields a bare status error.
func TestProbeEmptyBodyError(t *testing.T) {
	redact.Reset()
	defer redact.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	pc := newProviderClient()
	_, _, err := pc.probe(srv.URL, "")
	if err == nil || !strings.HasPrefix(err.Error(), "HTTP 503") {
		t.Fatalf("expected bare HTTP 503 error, got %v", err)
	}
}
