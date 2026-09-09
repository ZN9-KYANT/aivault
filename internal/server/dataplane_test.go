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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": payload["model"], "auth": r.Header.Get("Authorization"),
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