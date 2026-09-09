package server

// The OpenAI-compatible data plane (SPEC 6.1): downstream clients present a
// proxy key (Bearer vk-…), requests are routed to the provider named in the
// model namespace ("openai/gpt-5") or to an alias chain, the Authorization
// header is rewritten to the real credential, and errors are normalized to
// the OpenAI error shape (SPEC 6.1).
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
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/redact"
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
// requires a valid proxy key (SPEC 4.4).
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

// withProxyKey authenticates the downstream client and enforces the proxy
// key's rate/spend limits before the handler runs (SPEC 4.4, 8.8).
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
		if aerr := s.checkLimits(pk); aerr != nil {
			aerr.write(w)
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

// checkLimits enforces the proxy key's RPM and daily spend cap (SPEC 8.8).
func (s *Server) checkLimits(pk *proxykey.Key) *apiError {
	now := time.Now()
	if pk.RPM > 0 {
		if ok, retryAfter := s.limiter.allow(pk.ID, pk.RPM, now); !ok {
			return &apiError{
				status: http.StatusTooManyRequests, typ: "rate_limit_error",
				msg: fmt.Sprintf("proxy key %q exceeded %d requests/minute (retry after %.0fs)", pk.Name, pk.RPM, retryAfter.Seconds()),
				code: "rate_limit_exceeded",
			}
		}
	}
	if pk.MaxUSDPerDay > 0 {
		if usd := s.limiter.spendFor(pk.ID, now); usd >= pk.MaxUSDPerDay {
			return &apiError{
				status: http.StatusTooManyRequests, typ: "rate_limit_error",
				msg: fmt.Sprintf("proxy key %q reached its daily spend cap of $%.2f (spent $%.4f today)", pk.Name, pk.MaxUSDPerDay, usd),
				code: "spend_cap_reached",
			}
		}
	}
	return nil
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

// routeEntry is one hop in the resolved route: a provider and the model name
// to send upstream (SPEC 5, 6.1).
type routeEntry struct {
	providerID string
	model      string
}

// resolveRoute maps the request's model to a route: an alias chain (SPEC 5)
// when the name matches one, else a direct provider/model namespace split.
// Failover comes only from alias chains (SPEC 6.1, default off).
func resolveRoute(modelRaw string, meta *vault.Meta, pk *proxykey.Key) ([]routeEntry, bool, *apiError) {
	if chain, ok := meta.Aliases[modelRaw]; ok && len(chain) > 0 {
		entries := make([]routeEntry, 0, len(chain))
		for _, e := range chain {
			pid, m, err := provider.SplitModel(e)
			if err != nil {
				return nil, false, &apiError{
					status: http.StatusBadRequest, typ: "invalid_request_error",
					msg: "alias chain entry: " + err.Error(), code: "invalid_alias",
				}
			}
			entries = append(entries, routeEntry{providerID: pid, model: m})
		}
		if aerr := scopeCheck(entries, pk); aerr != nil {
			return nil, false, aerr
		}
		return entries, true, nil
	}
	pid, m, err := provider.SplitModel(modelRaw)
	if err != nil {
		return nil, false, &apiError{
			status: http.StatusBadRequest, typ: "invalid_request_error",
			msg:    "model must be namespaced as <provider>/<model> (e.g. openai/gpt-5) or a registered alias",
			code:   "invalid_model",
		}
	}
	entries := []routeEntry{{providerID: pid, model: m}}
	if aerr := scopeCheck(entries, pk); aerr != nil {
		return nil, false, aerr
	}
	return entries, false, nil
}

// scopeCheck requires every provider in the route to be in the proxy key's
// scope, so a failover chain cannot leak to an out-of-scope provider.
func scopeCheck(entries []routeEntry, pk *proxykey.Key) *apiError {
	if len(pk.Providers) == 0 {
		return nil
	}
	for _, e := range entries {
		if !containsString(pk.Providers, e.providerID) {
			return &apiError{
				status: http.StatusForbidden, typ: "invalid_request_error",
				msg:    fmt.Sprintf("provider %q is not allowed for this proxy key", e.providerID),
				code:   "provider_not_allowed",
			}
		}
	}
	return nil
}

// forward proxies suffix endpoints (chat/completions, responses, embeddings)
// to the provider named in the model namespace, following alias chains with
// optional failover on 429/5xx/timeout (SPEC 6.1).
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
	if modelRaw == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "model is required", "invalid_model")
		return
	}

	meta, err := vault.NewStore(s.opts.Home).LoadMeta()
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "api_error", "load meta: "+err.Error(), "internal_error")
		return
	}
	entries, isAlias, aerr := resolveRoute(modelRaw, meta, pk)
	if aerr != nil {
		aerr.write(w)
		return
	}
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "api_error", "load config: "+err.Error(), "internal_error")
		return
	}
	// Failover applies only to alias chains and only when enabled (SPEC 6.1:
	// configurable, default off).
	failover := isAlias && cfg.Failover && len(entries) > 1

	stream, _ := payload["stream"].(bool)
	for i, ent := range entries {
		tgt, raerr := s.resolveProvider(ent.providerID, meta)
		if raerr != nil {
			if failover && i < len(entries)-1 {
				continue
			}
			raerr.write(w)
			return
		}
		if tgt.cred != "" {
			s.touch() // keyring-using request resets the idle auto-lock (SPEC 4.2)
		}

		// Rewrite the body: the entry's model name (namespace stripped). The
		// JSON round-trip stores numbers as float64 — lossless for counts < 2^53.
		payload["model"] = ent.model
		outBody, err := json.Marshal(payload)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "encode request: "+err.Error(), "invalid_json")
			return
		}

		resp, err := s.doUpstream(r, tgt, suffix, outBody, stream)
		if err != nil {
			if failover && i < len(entries)-1 {
				continue
			}
			_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventKeyUse, Provider: ent.providerID, ProxyKeyID: pk.ID, Outcome: "upstream-error"})
			if errors.Is(err, context.DeadlineExceeded) {
				writeOpenAIError(w, http.StatusGatewayTimeout, "api_error", "provider request timed out", "timeout")
				return
			}
			writeOpenAIError(w, http.StatusBadGateway, "api_error", "provider request failed: "+err.Error(), "upstream_error")
			return
		}

		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			if failover && i < len(entries)-1 && retryableStatus(resp.StatusCode) {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				continue
			}
			_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventKeyUse, Provider: ent.providerID, ProxyKeyID: pk.ID, Outcome: fmt.Sprintf("%d", resp.StatusCode)})
			s.writeUpstreamError(w, resp)
			resp.Body.Close()
			return
		}

		_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventKeyUse, Provider: ent.providerID, ProxyKeyID: pk.ID, Outcome: fmt.Sprintf("%d", resp.StatusCode)})
		w.Header().Set("Content-Type", orDefault(resp.Header.Get("Content-Type"), "application/json"))
		w.WriteHeader(resp.StatusCode)
		if stream {
			n := pumpStream(w, resp)
			resp.Body.Close()
			s.accountStreamSpend(pk, ent, &cfg.Spend, n)
		} else {
			data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRequestBody))
			resp.Body.Close()
			if rerr != nil {
				return // headers already sent; nothing sane left to do
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
			_, _ = w.Write(data)
			s.accountUsageSpend(pk, ent, &cfg.Spend, data)
		}
		return
	}

	// Failover exhausted on pre-flight errors; nothing written yet.
	writeOpenAIError(w, http.StatusBadGateway, "api_error", "all providers in the failover chain failed", "upstream_error")
}

// doUpstream builds and performs one upstream request. Failover re-uses the
// caller's context, so client disconnects tear down in-flight providers.
func (s *Server) doUpstream(r *http.Request, tgt *target, suffix string, outBody []byte, stream bool) (*http.Response, error) {
	ctx := r.Context()
	if !stream {
		// Bounded deadline only for non-streaming requests; streams stay open.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, upstreamDeadline)
		defer cancel()
	}
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(tgt.baseURL, suffix), bytes.NewReader(outBody))
	if err != nil {
		return nil, err
	}
	out.Header.Set("Content-Type", "application/json")
	if tgt.cred != "" {
		out.Header.Set("Authorization", "Bearer "+tgt.cred)
	}
	for k, v := range tgt.headers {
		out.Header.Set(k, v)
	}
	return s.upstream.Do(out)
}

// retryableStatus reports whether failover should try the next chain entry.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// accountUsageSpend estimates and accrues the request cost for a completed
// non-streaming response, preferring the upstream usage block (SPEC 8.8).
func (s *Server) accountUsageSpend(pk *proxykey.Key, ent routeEntry, spend *config.Spend, body []byte) {
	if pk.MaxUSDPerDay <= 0 {
		return
	}
	in, out := spendPrice(spend, ent.providerID+"/"+ent.model)
	var u struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	var cost float64
	if json.Unmarshal(body, &u) == nil && u.Usage.PromptTokens+u.Usage.CompletionTokens > 0 {
		cost = float64(u.Usage.PromptTokens)/1e6*in + float64(u.Usage.CompletionTokens)/1e6*out
	} else {
		cost = float64(len(body)) / 4 / 1e6 * out // char/4 estimation fallback
	}
	if cost > 0 {
		s.limiter.addSpend(pk.ID, cost, time.Now())
	}
}

// accountStreamSpend estimates streamed responses by bytes/4 (SSE overhead
// included) at the output rate; a coarse but monotone cap signal (SPEC 8.8).
func (s *Server) accountStreamSpend(pk *proxykey.Key, ent routeEntry, spend *config.Spend, bytes int) {
	if pk.MaxUSDPerDay <= 0 || bytes <= 0 {
		return
	}
	_, out := spendPrice(spend, ent.providerID+"/"+ent.model)
	cost := float64(bytes) / 4 / 1e6 * out
	if cost > 0 {
		s.limiter.addSpend(pk.ID, cost, time.Now())
	}
}

// spendPrice returns the USD-per-1M-token estimate for a namespaced model;
// the first matching prefix in the config table wins (SPEC 8.8).
func spendPrice(cfg *config.Spend, model string) (in, out float64) {
	in, out = cfg.InputUSDPer1M, cfg.OutputUSDPer1M
	for _, mp := range cfg.ModelPrices {
		if mp.Prefix != "" && strings.HasPrefix(model, mp.Prefix) {
			return mp.InputUSDPer1M, mp.OutputUSDPer1M
		}
	}
	return in, out
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

// writeUpstreamError normalizes a non-2xx provider response to the OpenAI
// error JSON shape (SPEC 6.1): already-shaped bodies pass through untouched,
// anything else is wrapped with a bounded, redacted snippet (SPEC 8.4).
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
	msg := strings.TrimSpace(redact.String(string(data)))
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
// tokens reach the client live (SPEC 6.1), returning the bytes relayed.
func pumpStream(w http.ResponseWriter, resp *http.Response) int {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	total := 0
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			total += n
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return total // EOF or client/upstream disconnect
		}
	}
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

// writeOpenAIError renders errors in the OpenAI error JSON shape (SPEC 6.1),
// with every message run through the redaction filter (SPEC 8.4).
func writeOpenAIError(w http.ResponseWriter, status int, typ, msg string, code any) {
	writeJSON(w, status, map[string]any{
		"error": openAIErrorBody{Message: redact.String(msg), Type: typ, Code: code},
	})
}