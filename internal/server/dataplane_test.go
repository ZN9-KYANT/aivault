package server

// Data-plane integration tests (SPEC 6.1): a mock OpenAI-compatible upstream
// (httptest) behind a real gateway on an ephemeral loopback port.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/proxykey"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

// mockUpstream is an OpenAI-compatible upstream. Test scripts are passed in
// the request body itself via "__fail": "openai-shape" (429 shaped error) or
// "__fail": "plain" (500 plain text); normal requests echo the rewritten
// model and the Authorization header the gateway actually sent.
type mockUpstream struct {
	*httptest.Server
}

func newMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	m := &mockUpstream{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/models":
			fmt.Fprint(w, `{"object":"list","data":[{"id":"mock-small"},{"id":"mock-large"}]}`)
		case "/chat/completions":
			var payload map[string]any
			_ = json.Unmarshal(body, &payload)
			switch payload["__fail"] {
			case "openai-shape":
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"error":{"message":"slow down","type":"rate_limit_error","code":"rate_limit"}}`)
				return
			case "plain":
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "internal upstream meltdown")
				return
			}
			if stream, _ := payload["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				f := w.(http.Flusher)
				fmt.Fprint(w, "data: {\"delta\":\"chunk-1\"}\n\n")
				f.Flush()
				fmt.Fprint(w, "data: [DONE]\n\n")
				f.Flush()
				return
			}
			switch payload["__fail"] {
			case "leak":
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `upstream crashed while holding sk-leaky-credential-999999`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": payload["model"], "auth": r.Header.Get("Authorization"),
				"usage": map[string]int{"prompt_tokens": 1000, "completion_tokens": 1000},
			})
		default:
			fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
		}
	}))
	t.Cleanup(m.Server.Close)
	return m
}

// newGateway builds a vault home wired to a mock upstream: custom provider
// "mock" (apikey) and "mockfree" (none-kind), plus a scoped proxy key.
func newGateway(t *testing.T) (home, pass, proxyPlain string) {
	t.Helper()
	home, pass = newTestHome(t)
	mock := newMockUpstream(t)

	st := vault.NewStore(home)
	if err := st.Save("mock", []byte(pass), &vault.Payload{
		Version: vault.PayloadVersion, Provider: "mock", Kind: vault.KindAPIKey,
		APIKey: &vault.APIKey{Key: "sk-mock-key", BaseURL: mock.URL},
	}); err != nil {
		t.Fatal(err)
	}
	meta, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	meta.Providers["mock"] = vault.ProviderMeta{
		Kind: string(vault.KindAPIKey), BaseURL: mock.URL, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	meta.Providers["mockfree"] = vault.ProviderMeta{
		Kind: string(vault.KindNone), BaseURL: mock.URL, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	// Native builtin: registered (as after a future keys add) so the compat
	// branch in resolveProvider is exercised. No vault file — it must 400.
	meta.Providers["anthropic"] = vault.ProviderMeta{
		Kind: string(vault.KindAPIKey), BaseURL: "https://api.anthropic.com", Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.SaveMeta(meta); err != nil {
		t.Fatal(err)
	}

	pk, plain, err := proxykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pk.Name = "testapp"
	pk.Providers = []string{"mock", "mockfree"}
	if err := proxykey.NewStore(proxykey.DefaultPath(home)).Add(pk); err != nil {
		t.Fatal(err)
	}
	return home, pass, plain
}

// newStartedGateway starts the admin+data servers on ephemeral ports.
func newStartedGateway(t *testing.T, home string) (*Server, string) {
	t.Helper()
	s := New(Options{
		Home: home, ConfigPath: config.Path(home),
		SocketPath: SocketPath(home), Port: 0, DataPlane: true, AutoLockMins: 15,
	})
	aln, err := s.listen()
	if err != nil {
		t.Fatal(err)
	}
	s.httpSrv = &http.Server{Handler: s.adminRoutes()}
	go func() { _ = s.httpSrv.Serve(aln) }()
	dln, err := s.listenData()
	if err != nil {
		t.Fatal(err)
	}
	s.dataSrv = &http.Server{Handler: s.dataRoutes()}
	go func() { _ = s.dataSrv.Serve(dln) }()
	t.Cleanup(func() { s.shutdown("test") })
	return s, "http://" + dln.Addr().String()
}

// startGateway starts the servers and unlocks the keyring.
func startGateway(t *testing.T, home, pass string) (*Server, string) {
	t.Helper()
	s, dataURL := newStartedGateway(t, home)
	if _, err := s.unlock([]byte(pass)); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	return s, dataURL
}

func mustPost(t *testing.T, base, path, bearer, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestProxyKeyAuth(t *testing.T) {
	home, _, plain := newGateway(t)
	_, dataURL := newStartedGateway(t, home)

	// Missing header.
	req, _ := http.NewRequest("POST", dataURL+"/v1/chat/completions", bytes.NewBufferString("{}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing auth = %d, want 401", resp.StatusCode)
	}

	// Unknown key — must be OpenAI-shaped.
	resp = mustPost(t, dataURL, "/v1/chat/completions", "vk-unknown", `{"model":"mock/m1"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown key = %d, want 401", resp.StatusCode)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatalf("auth error not JSON: %s", data)
	}
	errObj, _ := body["error"].(map[string]any)
	if errObj == nil || errObj["message"] == "" || errObj["type"] != "authentication_error" {
		t.Fatalf("auth error shape = %s", data)
	}

	// Malformed (not vk-) key.
	resp = mustPost(t, dataURL, "/v1/chat/completions", "sk-bogus", `{"model":"mock/m1"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("malformed key = %d, want 401", resp.StatusCode)
	}

	// Revoked key.
	st := proxykey.NewStore(proxykey.DefaultPath(home))
	pk2, plain2, _ := proxykey.Generate()
	pk2.Name = "revoked"
	pk2.Providers = []string{"mock"}
	if err := st.Add(pk2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Revoke(pk2.ID); err != nil {
		t.Fatal(err)
	}
	resp = mustPost(t, dataURL, "/v1/chat/completions", plain2, `{"model":"mock/m1"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked key = %d, want 401", resp.StatusCode)
	}

	// Scope violation (testapp is scoped to "mock").
	resp = mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"openai/gpt-x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope provider = %d, want 403", resp.StatusCode)
	}
}

func TestChatNonStream(t *testing.T) {
	home, pass, plain := newGateway(t)
	_, dataURL := startGateway(t, home, pass)

	resp := mustPost(t, dataURL, "/v1/chat/completions", plain,
		`{"model":"mock/mock-small","messages":[{"role":"user","content":"hi"}],"temperature":0.7}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("response not JSON: %s", data)
	}
	if out["model"] != "mock-small" {
		t.Fatalf("upstream saw model %v, want mock-small (namespace stripped)", out["model"])
	}
	if out["auth"] != "Bearer sk-mock-key" {
		t.Fatalf("upstream saw auth %v", out["auth"])
	}
	entries, err := audit.Tail(home+"/audit.log", 100)
	if err != nil {
		t.Fatal(err)
	}
	sawUse := false
	for _, e := range entries {
		if e.Event == audit.EventKeyUse && e.Provider == "mock" && e.Outcome == "200" {
			sawUse = true
		}
	}
	if !sawUse {
		t.Fatalf("key.use audit entry missing: %+v", entries)
	}
}

func TestChatStream(t *testing.T) {
	home, pass, plain := newGateway(t)
	_, dataURL := startGateway(t, home, pass)

	resp := mustPost(t, dataURL, "/v1/chat/completions", plain,
		`{"model":"mock/mock-small","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type = %q, want text/event-stream", ct)
	}
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "data: {\"delta\":\"chunk-1\"}") ||
		!strings.Contains(string(data), "data: [DONE]") {
		t.Fatalf("SSE body missing chunks: %s", data)
	}
}

func TestChatRoutingErrors(t *testing.T) {
	home, pass, plain := newGateway(t)
	s, dataURL := startGateway(t, home, pass)

	// An unscoped key (empty scope = all providers) for compat/unknown tests.
	pkAll, plainAll, _ := proxykey.Generate()
	pkAll.Name = "allaccess"
	if err := proxykey.NewStore(proxykey.DefaultPath(home)).Add(pkAll); err != nil {
		t.Fatal(err)
	}
	_ = plain

	// Incompatible native builtin.
	resp := mustPost(t, dataURL, "/v1/chat/completions", plainAll, `{"model":"anthropic/claude"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "not OpenAI wire-compatible") {
		t.Fatalf("anthropic route = %d %s", resp.StatusCode, data)
	}

	// Unnamespaced model.
	resp = mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"gpt-5"}`)
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "namespaced") {
		t.Fatalf("bare model = %d %s", resp.StatusCode, data)
	}

	// Unknown provider.
	resp = mustPost(t, dataURL, "/v1/chat/completions", plainAll, `{"model":"nosuch/m1"}`)
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "unknown provider") {
		t.Fatalf("unknown provider = %d %s", resp.StatusCode, data)
	}

	// Locked gateway for an apikey provider.
	s.lockFor("test-lock")
	resp = mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/m1"}`)
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(data), "gateway is locked") {
		t.Fatalf("locked gateway = %d %s", resp.StatusCode, data)
	}
}

func TestUpstreamErrorShapes(t *testing.T) {
	home, pass, plain := newGateway(t)
	_, dataURL := startGateway(t, home, pass)

	// Already OpenAI-shaped upstream error passes through untouched.
	resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small","__fail":"openai-shape"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(data), `"type":"rate_limit_error"`) {
		t.Fatalf("shaped upstream error = %d %s", resp.StatusCode, data)
	}

	// Plain-text upstream error is wrapped.
	resp = mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small","__fail":"plain"}`)
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(string(data), `"type":"api_error"`) {
		t.Fatalf("plain upstream error = %d %s", resp.StatusCode, data)
	}
}

func TestModelsEndpoint(t *testing.T) {
	home, pass, plain := newGateway(t)
	_, dataURL := startGateway(t, home, pass)

	req, _ := http.NewRequest("GET", dataURL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("models = %d %s", resp.StatusCode, data)
	}
	var out struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse models: %s", data)
	}
	if out.Object != "list" || len(out.Data) != 4 ||
		out.Data[0].ID != "mock/mock-small" || out.Data[1].ID != "mock/mock-large" ||
		out.Data[2].ID != "mockfree/mock-small" || out.Data[3].ID != "mockfree/mock-large" {
		t.Fatalf("models body = %s", data)
	}
}

func TestCredentialFreeRouting(t *testing.T) {
	home, pass, plain := newGateway(t)
	_, dataURL := startGateway(t, home, pass)

	// "mockfree" is a none-kind provider: forwarded WITHOUT an Authorization
	// header (SPEC 3.4) and without needing the keyring.
	resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mockfree/mock-small"}`)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("not JSON: %s", data)
	}
	if auth, _ := out["auth"].(string); auth != "" {
		t.Fatalf("credential-free provider must not carry auth, got %q", auth)
	}
	if out["model"] != "mock-small" {
		t.Fatalf("model not stripped: %v", out["model"])
	}
}

func TestUnknownEndpointOpenAIShape(t *testing.T) {
	home, _, plain := newGateway(t)
	_, dataURL := newStartedGateway(t, home)

	req, _ := http.NewRequest("GET", dataURL+"/v1/nothing", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatalf("404 not JSON: %s", data)
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf("404 not OpenAI-shaped: %s", data)
	}
}
func TestRateLimit(t *testing.T) {
	home, pass, _ := newGateway(t)
	s, dataURL := startGateway(t, home, pass)
	_ = s

	pk, plain, _ := proxykey.Generate()
	pk.Name = "rpm2"
	pk.Providers = []string{"mock"}
	pk.RPM = 2
	if err := proxykey.NewStore(proxykey.DefaultPath(home)).Add(pk); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 2; i++ {
		resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, resp.StatusCode)
		}
	}
	resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(data), "rate_limit_exceeded") {
		t.Fatalf("third request = %d %s, want 429 rate_limit_exceeded", resp.StatusCode, data)
	}
}

func TestSpendCap(t *testing.T) {
	home, pass, _ := newGateway(t)
	s, dataURL := startGateway(t, home, pass)
	_ = s

	pk, plain, _ := proxykey.Generate()
	pk.Name = "capped"
	pk.Providers = []string{"mock"}
	pk.MaxUSDPerDay = 0.002 // mock usage: 1000+1000 tokens @ $0.5/$1.5 per 1M = $0.002
	if err := proxykey.NewStore(proxykey.DefaultPath(home)).Add(pk); err != nil {
		t.Fatal(err)
	}

	resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request = %d %s, want 200 (usage accounted)", resp.StatusCode, data)
	}

	resp = mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small"}`)
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(data), "spend_cap_reached") {
		t.Fatalf("second request = %d %s, want 429 spend_cap_reached", resp.StatusCode, data)
	}
}

func TestAliasFailover(t *testing.T) {
	home, pass, _ := newGateway(t)

	// Register a failing provider in front of the good one: always 429.
	bad := newFailingUpstream(t, http.StatusTooManyRequests,
		`{"error":{"message":"slow down","type":"rate_limit_error","code":"rate_limit"}}`)
	st := vault.NewStore(home)
	if err := st.Save("mockbad", []byte(pass), &vault.Payload{
		Version: vault.PayloadVersion, Provider: "mockbad", Kind: vault.KindAPIKey,
		APIKey: &vault.APIKey{Key: "sk-mock-bad", BaseURL: bad.URL},
	}); err != nil {
		t.Fatal(err)
	}
	meta, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	meta.Providers["mockbad"] = vault.ProviderMeta{
		Kind: string(vault.KindAPIKey), BaseURL: bad.URL, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	meta.Aliases = map[string][]string{
		"best": {"mockbad/dead", "mock/mock-small"},
	}
	if err := st.SaveMeta(meta); err != nil {
		t.Fatal(err)
	}

	plain := newScopedKey(t, home, "failover-app", []string{"mock", "mockbad", "mockfree"})

	// Failover OFF (default): the failing first entry's error is returned.
	s, dataURL := startGateway(t, home, pass)
	resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"best"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("failover off: = %d %s, want the 429 passthrough", resp.StatusCode, data)
	}
	shutdownForTest(s)

	// flip config failover on
	if err := setFailover(home, true); err != nil {
		t.Fatal(err)
	}
	s2, dataURL2 := newStartedGateway(t, home)
	if _, err := s2.unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	resp = mustPost(t, dataURL2, "/v1/chat/completions", plain, `{"model":"best"}`)
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failover on: = %d %s, want fallback success", resp.StatusCode, data)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("not JSON: %s", data)
	}
	if out["model"] != "mock-small" {
		t.Fatalf("fallback model = %v, want mock-small", out["model"])
	}
}

// newFailingUpstream returns an upstream that always answers with status+body.
func newFailingUpstream(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(b.Close)
	return b
}

// newScopedKey issues a proxy key and returns its plaintext (shown once).
func newScopedKey(t *testing.T, home, name string, providers []string) string {
	t.Helper()
	pk, plain, err := proxykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pk.Name = name
	pk.Providers = providers
	if err := proxykey.NewStore(proxykey.DefaultPath(home)).Add(pk); err != nil {
		t.Fatal(err)
	}
	return plain
}

func shutdownForTest(s *Server) { s.shutdown("test") }

// setFailover toggles the failover flag in the home's config.toml.
func setFailover(home string, on bool) error {
	cfg, err := config.Load(config.Path(home))
	if err != nil {
		return err
	}
	cfg.Failover = on
	return config.Save(config.Path(home), cfg)
}

func TestRedactionInErrors(t *testing.T) {
	home, pass, _ := newGateway(t)
	s, dataURL := startGateway(t, home, pass)

	// The mock's plain-fail body echoes a credential-shaped string; the
	// gateway must redact it before wrapping.
	if _, err := s.unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	plain := newScopedKey(t, home, "redact-app", []string{"mock"})
	resp := mustPost(t, dataURL, "/v1/chat/completions", plain, `{"model":"mock/mock-small","__fail":"leak"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(data), "sk-leaky-credential-999999") {
		t.Fatalf("upstream error leaked credential: %s", data)
	}
}
