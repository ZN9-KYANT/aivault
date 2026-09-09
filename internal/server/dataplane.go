package server

// The OpenAI-compatible data plane (SPEC 6.1): downstream clients present a
// proxy key (Bearer vk-…), requests are routed to the provider named in the
// model namespace ("openai/gpt-5"), the Authorization header is rewritten to
// the real credential, and errors are normalized to the OpenAI error shape.
// Failover chains and aliases arrive with the hardening milestone (SPEC 6.1).
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/proxykey"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

const (
	maxRequestBody   = 16 << 20 // 16 MiB
	upstreamDeadline = 120 * time.Second
	modelsCacheTTL   = 10 * time.Minute
	maxErrorSnippet  = 300
)

// modelsEntry caches one provider's /models IDs (SPEC 5).
type modelsEntry struct {
	ids []string
	at  time.Time
}

// apiError is an internal error carrying its OpenAI error rendering.
type apiError struct {
	status int
	typ    string // "invalid_request_error" | "api_error" | "authentication_error"
	msg    string
	code   any
}

func (e *apiError) write(w http.ResponseWriter) {
	writeOpenAIError(w, e.status, e.typ, e.msg, e.code)
}

// dataRoutes builds the OpenAI-compatible data plane (SPEC 6.1). Every route
// requires a valid proxy key (SPEC 4.4). Aliases + failover: hardening.
func (s *Server) dataRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/models", s.withProxyKey(s.handleModels))
	mux.Handle("POST /v1/chat/completions", s.withProxyKey(func(w http.ResponseWriter, r *http.Request, pk *proxykey.Key) {
		s.forward(w, r, "chat/completions", pk)
	}))
	mux.Handle("POST /v1/responses", s.withProxyKey(func(w http.ResponseWriter, r *http.Request, pk *proxykey.Key) {
		s.forward(w, r, "responses", pk)
	}))
	mux.Handle("POST /v1/embeddings", s.withProxyKey(func(w http.ResponseWriter, r *http.Request, pk *proxykey.Key) {
		s.forward(w, r, "embeddings", pk)
	}))
	// OpenAI-shaped 404 for everything else.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeOpenAIError(w, http.StatusNotFound, "invalid_request_error", "unknown endpoint: "+r.URL.Path, "not_found")
	})
	return mux
}

// withProxyKey authenticates the downstream client before the handler runs.
func (s *Server) withProxyKey(next func(http.ResponseWriter, *http.Request, *proxykey.Key)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pk, err := s.authProxyKey(r)
		if err != nil {
			id := ""
			if pk != nil {
				id = pk.ID
			}
			_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventAuthFail, ProxyKeyID: id, Outcome: err.Error()})
			writeOpenAIError(w, http.StatusUnauthorized, "authentication_error", err.Error(), "invalid_api_key")
			return
		}
		next(w, r, pk)
	})
}

// authProxyKey validates the Authorization header against proxykeys.json
// (SHA-256 lookup, constant time per digest — SPEC 4.4, 8.5). A revoked key
// authenticates as revoked so the audit log can distinguish the case.
func (s *Server) authProxyKey(r *http.Request) (*proxykey.Key, error) {
	const bearer = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, bearer) {
		return nil, errors.New("missing bearer proxy key")
	}
	plaintext := auth[len(bearer):]
	if !strings.HasPrefix(plaintext, "vk-") {
		return nil, errors.New("malformed proxy key")
	}
	found, err := proxykey.NewStore(proxykey.DefaultPath(s.opts.Home)).Lookup(plaintext)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, errors.New("unknown proxy key")
	}
	if found.Revoked {
		return found, errors.New("revoked proxy key")
	}
	return found, nil
}

// target is the resolved upstream destination for one request.
type target struct {
	baseURL string
	cred    string            // empty for credential-free providers
	headers map[string]string // per-provider custom headers (SPEC 3.4)
}

// resolveProvider maps a provider ID to its credential/endpoint (SPEC 4.4, 5).
func (s *Server) resolveProvider(providerID string, meta *vault.Meta) (*target, *apiError) {
	pm, ok := meta.Providers[providerID]
	if !ok {
		return nil, &apiError{
			status: http.StatusBadRequest, typ: "invalid_request_error",
			msg:    fmt.Sprintf("unknown provider %q", providerID),
			code:   "unknown_provider",
		}
	}
	if !pm.Enabled {
		return nil, &apiError{
			status: http.StatusBadRequest, typ: "invalid_request_error",
			msg:    fmt.Sprintf("provider %q is disabled", providerID),
			code:   "provider_disabled",
		}
	}
	// Native (non-OpenAI-wire) builtins need translation shims (SPEC 5, 10).
	if p, isBuiltin := provider.BuiltinByID(providerID); isBuiltin && !p.OpenAICompat {
		return nil, &apiError{
			status: http.StatusBadRequest, typ: "invalid_request_error",
			msg: fmt.Sprintf("provider %q is not OpenAI wire-compatible; translation shims arrive in v1.1", providerID),
			code: "unsupported_provider",
		}
	}
	if pm.Kind == string(vault.KindNone) {
		// Credential-free local server (SPEC 3.4): base URL from meta.json.
		return &target{baseURL: pm.BaseURL}, nil
	}
	p, unlocked := s.ring.Get(providerID)
	if !unlocked || p == nil || p.APIKey == nil {
		return nil, &apiError{
			status: http.StatusServiceUnavailable, typ: "api_error",
			msg:  "gateway is locked — run aivault unlock",
			code: "gateway_locked",
		}
	}
	baseURL := p.APIKey.BaseURL
	if baseURL == "" {
		baseURL = pm.BaseURL
	}
	return &target{baseURL: baseURL, cred: p.APIKey.Key, headers: p.APIKey.Headers}, nil
}

// forward proxies suffix endpoints (chat/completions, responses, embeddings)
// to the provider named in the model namespace (SPEC 6.1).
func (s *Server) forward(w http.ResponseWriter, r *http.Request, suffix string, pk *proxykey.Key) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "read request body: "+err.Error(), "bad_request")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil || payload == nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "request body must be a JSON object", "invalid_json")
		return
	}
	modelRaw, _ := payload["model"].(string)
	providerID, modelName, err := splitModel(modelRaw)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error",
			"model must be namespaced as <provider>/<model> (e.g. openai/gpt-5)", "invalid_model")
		return
	}
	if len(pk.Providers) > 0 && !containsString(pk.Providers, providerID) {
		writeOpenAIError(w, http.StatusForbidden, "invalid_request_error",
			fmt.Sprintf("provider %q is not allowed for this proxy key", providerID), "provider_not_allowed")
		return
	}

	meta, err := vault.NewStore(s.opts.Home).LoadMeta()
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "api_error", "load meta: "+err.Error(), "internal_error")
		return
	}
	tgt, aerr := s.resolveProvider(providerID, meta)
	if aerr != nil {
		aerr.write(w)
		return
	}
	if tgt.cred != "" {
		s.touch() // keyring-using request resets the idle auto-lock (SPEC 4.2)
	}

	// Rewrite the body: strip the namespace from "model" (SPEC 6.1). The JSON
	// round-trip stores numbers as float64 — lossless for token counts < 2^53.
	payload["model"] = modelName
	outBody, err := json.Marshal(payload)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "encode request: "+err.Error(), "invalid_json")
		return
	}

	stream, _ := payload["stream"].(bool)
	ctx := r.Context()
	if !stream {
		// Bounded deadline only for non-streaming requests; streams stay open.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, upstreamDeadline)
		defer cancel()
	}
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(tgt.baseURL, suffix), bytes.NewReader(outBody))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "api_error", "build upstream request: "+err.Error(), "internal_error")
		return
	}
	out.Header.Set("Content-Type", "application/json")
	if tgt.cred != "" {
		out.Header.Set("Authorization", "Bearer "+tgt.cred)
	}
	for k, v := range tgt.headers {
		out.Header.Set(k, v)
	}

	resp, err := s.upstream.Do(out)
	if err != nil {
		_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventKeyUse, Provider: providerID, ProxyKeyID: pk.ID, Outcome: "upstream-error"})
		if errors.Is(err, context.DeadlineExceeded) {
			writeOpenAIError(w, http.StatusGatewayTimeout, "api_error", "provider request timed out", "timeout")
			return
		}
		writeOpenAIError(w, http.StatusBadGateway, "api_error", "provider request failed: "+err.Error(), "upstream_error")
		return
	}
	defer resp.Body.Close()

	_ = audit.Log(s.auditLog, audit.Entry{
		Event: audit.EventKeyUse, Provider: providerID, ProxyKeyID: pk.ID,
		Outcome: fmt.Sprintf("%d", resp.StatusCode),
	})

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		s.writeUpstreamError(w, resp)
		return
	}

	w.Header().Set("Content-Type", orDefault(resp.Header.Get("Content-Type"), "application/json"))
	w.WriteHeader(resp.StatusCode)
	if stream {
		pumpStream(w, resp)
		return
	}
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	}
	_, _ = io.Copy(w, resp.Body)
}

// writeUpstreamError normalizes a non-2xx provider response to the OpenAI
// error JSON shape (SPEC 6.1): already-shaped bodies pass through untouched,
// anything else is wrapped with a bounded snippet.
func (s *Server) writeUpstreamError(w http.ResponseWriter, resp *http.Response) {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRequestBody))
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) == nil {
		if _, has := probe["error"]; has {
			w.Header().Set("Content-Type", orDefault(resp.Header.Get("Content-Type"), "application/json"))
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(data)
			return
		}
	}
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		msg = resp.Status
	}
	if len(msg) > maxErrorSnippet {
		msg = msg[:maxErrorSnippet] + "…"
	}
	typ := "api_error"
	if resp.StatusCode < 500 {
		typ = "upstream_request_error"
	}
	writeOpenAIError(w, resp.StatusCode, typ, msg, resp.StatusCode)
}

// pumpStream relays an SSE body chunk by chunk, flushing after each write so
// tokens reach the client live (SPEC 6.1). The upstream request is bound to
// the client's context, so a disconnect tears down the upstream request.
func pumpStream(w http.ResponseWriter, resp *http.Response) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return // EOF or client/upstream disconnect
		}
	}
}

func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request, pk *proxykey.Key) {
	s.touch()
	meta, err := vault.NewStore(s.opts.Home).LoadMeta()
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "api_error", "load meta: "+err.Error(), "internal_error")
		return
	}
	scope := pk.Providers
	if len(scope) == 0 { // empty scope = all registered providers
		for id := range meta.Providers {
			scope = append(scope, id)
		}
	}
	type modelDoc struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	docs := []modelDoc{}
	for _, id := range scope {
		ids, aerr := s.modelsFor(id, meta)
		if aerr != nil {
			continue // a broken provider must not hide the rest
		}
		for _, id2 := range ids {
			docs = append(docs, modelDoc{ID: id2, Object: "model", OwnedBy: id})
		}
	}
	_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventKeyUse, ProxyKeyID: pk.ID, Outcome: "models"})
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": docs})
}

// modelsFor returns provider-namespaced model IDs ("openai/gpt-5") from the
// per-provider /models cache, refreshing it past the TTL (SPEC 5, 6.1).
func (s *Server) modelsFor(providerID string, meta *vault.Meta) ([]string, error) {
	pm, ok := meta.Providers[providerID]
	if !ok || !pm.Enabled {
		return nil, fmt.Errorf("provider %q not registered or disabled", providerID)
	}
	// Native builtins are not OpenAI wire-compatible (SPEC 5, 10).
	if p, isBuiltin := provider.BuiltinByID(providerID); isBuiltin && !p.OpenAICompat {
		return nil, fmt.Errorf("provider %q not wire-compatible", providerID)
	}

	s.modelsMu.Lock()
	defer s.modelsMu.Unlock()
	if e, ok := s.modelsCache[providerID]; ok && time.Since(e.at) < modelsCacheTTL {
		return e.ids, nil
	}

	// Resolve the credential for the /models fetch.
	var tgt *target
	var aerr *apiError
	if pm.Kind == string(vault.KindNone) {
		tgt = &target{baseURL: pm.BaseURL}
	} else {
		tgt, aerr = s.resolveProvider(providerID, meta)
		if aerr != nil {
			return nil, errors.New(aerr.msg)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamDeadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(tgt.baseURL, "models"), nil)
	if err != nil {
		return nil, err
	}
	if tgt.cred != "" {
		req.Header.Set("Authorization", "Bearer "+tgt.cred)
	}
	for k, v := range tgt.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.upstream.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch models for %s: %w", providerID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("fetch models for %s: HTTP %d", providerID, resp.StatusCode)
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse models for %s: %w", providerID, err)
	}
	ids := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		if m.ID == "" {
			continue
		}
		ids = append(ids, providerID+"/"+m.ID)
	}
	s.modelsCache[providerID] = modelsEntry{ids: ids, at: time.Now()}
	return ids, nil
}

func (s *Server) clearModelsCache() {
	s.modelsMu.Lock()
	s.modelsCache = make(map[string]modelsEntry)
	s.modelsMu.Unlock()
}

// splitModel splits "provider/model" at the FIRST slash; the model part may
// itself contain slashes (e.g. openrouter/meta-llama/llama-3).
func splitModel(raw string) (string, string, error) {
	i := strings.IndexByte(raw, '/')
	if i <= 0 || i == len(raw)-1 {
		return "", "", fmt.Errorf("invalid model %q", raw)
	}
	providerID, model := raw[:i], raw[i+1:]
	if !provider.ValidID(providerID) {
		return "", "", fmt.Errorf("invalid provider namespace %q", providerID)
	}
	return providerID, model, nil
}

func joinURL(base, suffix string) string {
	return strings.TrimRight(base, "/") + "/" + suffix
}

func containsString(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

type openAIErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
	Param   any    `json:"param,omitempty"`
	Code    any    `json:"code,omitempty"`
}

// writeOpenAIError renders errors in the OpenAI error JSON shape (SPEC 6.1).
func writeOpenAIError(w http.ResponseWriter, status int, typ, msg string, code any) {
	writeJSON(w, status, map[string]any{
		"error": openAIErrorBody{Message: msg, Type: typ, Code: code},
	})
}