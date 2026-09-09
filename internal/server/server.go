// Package server runs the aivault gateway: the OpenAI-compatible data plane
// on :8317 and the admin plane over a unix socket (SPEC 2, 6). This file
// implements the admin plane and keyring lifecycle (SPEC 4.2, 4.3, 6.2);
// the data plane arrives with the proxy-key milestone (SPEC 6.1).
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/keyring"
	"github.com/ZN9-KYANT/aivault/internal/kdf"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

// Options configure the gateway (SPEC 6).
type Options struct {
	Home         string // aivault home: vault files + audit log
	ConfigPath   string // config.toml (may be overridden by serve --config)
	SocketPath   string // admin unix socket, e.g. ~/.aivault/aivault.sock
	Port         int    // data-plane port, bound to 127.0.0.1 only (SPEC 6.1, 8.7)
	DataPlane    bool   // serve the OpenAI-compatible /v1 data plane on Port
	AutoLockMins int    // keyring auto-lock idle timeout; 0 disables (SPEC 4.2)
}

// Status is the admin-plane status document (SPEC 6.2).
type Status struct {
	Locked          bool     `json:"locked"`
	Providers       int      `json:"providers"`
	ProviderIDs     []string `json:"provider_ids,omitempty"`
	AutoLockMinutes int      `json:"auto_lock_minutes"`
	IdleMinutes     float64  `json:"idle_minutes"`
}

// Server is the aivault gateway process.
type Server struct {
	opts     Options
	auditLog string
	ring     *keyring.Keyring

	mu           sync.Mutex
	httpSrv      *http.Server
	dataSrv      *http.Server
	autoLockMins int
	lastActive   time.Time // last request that used the keyring (SPEC 4.2)

	upstream    *http.Client            // provider requests (SPEC 6.1)
	modelsMu    sync.Mutex
	modelsCache map[string]modelsEntry // provider → cached /models (SPEC 5)
}

// New returns a Server with the given options.
func New(opts Options) *Server {
	return &Server{
		opts:         opts,
		auditLog:     filepath.Join(opts.Home, "audit.log"),
		ring:         keyring.New(),
		autoLockMins: opts.AutoLockMins,
		modelsCache:  make(map[string]modelsEntry),
		upstream: &http.Client{
			// No overall Timeout: streaming responses must stay open (SPEC 6.1).
			// Non-streaming requests apply a context deadline instead.
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 120 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}
}

// SocketPath returns the admin socket path under the aivault home (SPEC 4.3).
func SocketPath(home string) string { return filepath.Join(home, "aivault.sock") }

// Run blocks serving the admin plane (unix socket) and — when enabled — the
// OpenAI-compatible data plane on 127.0.0.1:Port (SPEC 4.2, 4.3, 6.1, 6.2):
// the keyring is zeroized and sockets removed on any exit path.
func (s *Server) Run() error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.httpSrv = &http.Server{Handler: s.adminRoutes()}
	var dataLn net.Listener
	if s.opts.DataPlane {
		dataLn, err = s.listenData()
		if err == nil {
			s.dataSrv = &http.Server{Handler: s.dataRoutes()}
		}
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if dataLn != nil {
		fmt.Fprintf(os.Stderr, "data plane: http://%s (loopback only, SPEC 8.7)\n", dataLn.Addr())
	}

	// Idle auto-lock reaper (SPEC 4.2): cheap 1 s polling next to the
	// minute-scale timeout.
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				s.sweepIdle(now)
			}
		}
	}()

	errCh := make(chan error, 2)
	serve := func(srv *http.Server, l net.Listener) {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}
	go serve(s.httpSrv, ln)
	if s.dataSrv != nil {
		go serve(s.dataSrv, dataLn)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	select {
	case err := <-errCh:
		s.shutdown("listener-failed")
		return err
	case sig := <-sigCh:
		reason := "shutdown"
		if sig == syscall.SIGHUP {
			reason = "sighup" // SPEC 4.2: lock on SIGHUP
		}
		s.shutdown(reason)
		return nil
	}
}

// Shutdown stops the server: closes the listener, zeroizes the keyring and
// removes the socket (SPEC 4.2). Run also calls it on its exit paths; this
// exported form exists for tests and future embedding.
func (s *Server) Shutdown() { s.shutdown("shutdown") }

// listen creates the admin unix socket with stale-file handling and a
// peer-credential gate (SPEC 4.3).
func (s *Server) listen() (net.Listener, error) {
	path := s.opts.SocketPath
	if _, err := os.Stat(path); err == nil {
		// A connectable socket means another server is live.
		if c, derr := net.DialTimeout("unix", path, 500*time.Millisecond); derr == nil {
			c.Close()
			return nil, fmt.Errorf("server: %s is already served by a running aivault (is `aivault serve` up?)", path)
		}
		// Stale socket file from a crashed server — remove it.
		if rmErr := os.Remove(path); rmErr != nil {
			return nil, fmt.Errorf("server: remove stale socket: %w", rmErr)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("server: stat %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("server: listen %s: %w", path, err)
	}
	// Best-effort 0600 on the socket file (SPEC 8.2). On Windows mode bits
	// are advisory and peer-UID checks are unavailable, so the 0700 home
	// directory carries the protection; see checkPeerCred.
	_ = os.Chmod(path, 0o600)
	return &credListener{Listener: ln}, nil
}

// listenData binds the OpenAI-compatible data plane to 127.0.0.1 only
// (SPEC 6.1, 8.7: non-loopback binds require TLS, which v1.0 does not offer).
func (s *Server) listenData() (net.Listener, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", s.opts.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("server: data plane listen %s: %w", addr, err)
	}
	return ln, nil
}

// adminRoutes builds the admin-plane handler (SPEC 6.2). Provider/key/proxy-key
// CRUD arrives with the hardening milestone.
func (s *Server) adminRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1admin/status", s.handleStatus)
	mux.HandleFunc("POST /v1admin/unlock", s.handleUnlock)
	mux.HandleFunc("POST /v1admin/lock", s.handleLock)
	mux.HandleFunc("GET /v1admin/audit", s.handleAudit)
	return mux
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.statusSnapshot())
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		return
	}
	if req.Passphrase == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"missing passphrase"})
		return
	}
	_, err := s.unlock([]byte(req.Passphrase))
	if err != nil {
		if errors.Is(err, kdf.ErrWrongPassphrase) {
			_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventAuthFail, Outcome: "wrong-passphrase"})
			writeJSON(w, http.StatusUnauthorized, errBody{"wrong passphrase"})
			return
		}
		_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventUnlock, Outcome: "error"})
		writeJSON(w, http.StatusInternalServerError, errBody{err.Error()})
		return
	}
	_ = audit.Log(s.auditLog, audit.Entry{Event: audit.EventUnlock, Outcome: "ok"})
	writeJSON(w, http.StatusOK, s.statusSnapshot())
}

func (s *Server) handleLock(w http.ResponseWriter, _ *http.Request) {
	s.lockFor("manual")
	writeJSON(w, http.StatusOK, s.statusSnapshot())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	n := 50
	if q := r.URL.Query().Get("tail"); q != "" {
		v, err := strconv.Atoi(q)
		if err != nil || v < 0 {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid tail value"})
			return
		}
		if v > 10000 {
			v = 10000
		}
		n = v
	}
	entries, err := audit.Tail(s.auditLog, n)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Entries []audit.Entry `json:"entries"`
	}{entries})
}

// unlock verifies the passphrase against the config verifier blob (constant
// time, no vault file touched — SPEC 4.1), then decrypts every enabled
// apikey provider. The keyring is swapped only when ALL files decrypt; a
// failure leaves the current keyring untouched.
func (s *Server) unlock(passphrase []byte) (int, error) {
	// Reload config per unlock: a `passwd` run while serving re-wrapped the
	// verifier, and the fresh copy must be used.
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		return 0, fmt.Errorf("server: load config: %w", err)
	}
	if err := cfg.VerifyPassphrase(passphrase); err != nil {
		return 0, err
	}

	creds, err := s.decryptAll(passphrase)
	if err != nil {
		return 0, err
	}
	n := len(creds)
	s.ring.Unlock(creds) // takes ownership; zeroizes any previous contents (SPEC 4.2)
	s.clearModelsCache() // cached /models were fetched under possibly-rotated keys
	s.touch()
	return n, nil
}

// decryptAll decrypts every enabled apikey provider file. On error it
// zeroizes whatever was partially decrypted and returns nil — the caller
// never sees a partial map.
func (s *Server) decryptAll(passphrase []byte) (map[string]*vault.Payload, error) {
	st := vault.NewStore(s.opts.Home)
	meta, err := st.LoadMeta()
	if err != nil {
		return nil, fmt.Errorf("server: load meta: %w", err)
	}
	creds := make(map[string]*vault.Payload)
	for id, pm := range meta.Providers {
		if !pm.Enabled || pm.Kind != string(vault.KindAPIKey) {
			continue
		}
		if !hasVaultFile(st, id) {
			// Dangling index entry (e.g. a crash between keys remove's file
			// deletion and meta update): nothing to decrypt, skip.
			continue
		}
		p, err := st.Load(id, passphrase)
		if err != nil {
			keyring.Discard(creds)
			return nil, fmt.Errorf("server: decrypt %s: %w", id, err)
		}
		creds[id] = p
	}
	return creds, nil
}

// hasVaultFile reports whether vault/<provider>.json.age exists.
func hasVaultFile(st *vault.Store, id string) bool {
	_, err := os.Stat(st.ProviderPath(id))
	return err == nil
}

// lockFor zeroizes the keyring and audits the reason; locking an already
// locked keyring is a no-op (SPEC 4.2).
func (s *Server) lockFor(reason string) {
	if !s.ring.Unlocked() {
		return
	}
	s.ring.Lock()
	if err := audit.Log(s.auditLog, audit.Entry{Event: audit.EventLock, Outcome: reason}); err != nil {
		fmt.Fprintf(os.Stderr, "server: audit log: %v\n", err)
	}
}

// touch records keyring activity for the idle auto-lock (SPEC 4.2). Only
// requests that use the keyring count: unlock today, data-plane requests
// later. Read-only status/audit polls deliberately do not reset the timer —
// a poller must not keep the vault unlocked forever.
func (s *Server) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

// sweepIdle locks the keyring when idle time exceeds the auto-lock timeout
// (SPEC 4.2). Returns true if it locked. A non-positive timeout disables it.
func (s *Server) sweepIdle(now time.Time) bool {
	if s.autoLockMins <= 0 || !s.ring.Unlocked() {
		return false
	}
	s.mu.Lock()
	idle := now.Sub(s.lastActive)
	s.mu.Unlock()
	if idle < time.Duration(s.autoLockMins)*time.Minute {
		return false
	}
	s.lockFor("idle-timeout")
	return true
}

func (s *Server) statusSnapshot() Status {
	ids := s.ring.Providers()
	st := Status{
		Locked:          !s.ring.Unlocked(),
		Providers:       len(ids),
		ProviderIDs:     ids,
		AutoLockMinutes: s.autoLockMins,
	}
	if !st.Locked {
		s.mu.Lock()
		idle := time.Since(s.lastActive)
		s.mu.Unlock()
		st.IdleMinutes = idle.Minutes()
	}
	return st
}

// shutdown closes both planes, zeroizes the keyring and removes the socket
// file (SPEC 4.2: lock on SIGHUP or server shutdown). Safe to call twice.
func (s *Server) shutdown(reason string) {
	s.mu.Lock()
	srv := s.httpSrv
	data := s.dataSrv
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	if data != nil {
		_ = data.Close()
	}
	s.lockFor(reason)
	_ = os.Remove(s.opts.SocketPath)
}

// credListener gates each accepted connection on peer credentials where the
// OS supports them (SPEC 4.3).
type credListener struct{ net.Listener }

func (l *credListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := checkPeerCred(conn); err != nil {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// --- small HTTP helpers ---

type errBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return err
	}
	return nil
}