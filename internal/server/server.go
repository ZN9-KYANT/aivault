// Package server runs the aivault gateway: the OpenAI-compatible data plane
// on :8317 and the admin plane over a unix socket (SPEC 2, 6).
package server

import (
	"github.com/ZN9-KYANT/aivault/internal/errs"
)

// Options configure the gateway (SPEC 6).
type Options struct {
	Port       int    // default 8317
	SocketPath string // admin unix socket, e.g. ~/.aivault/aivault.sock
	TLSCert    string // required for non-loopback binds (SPEC 8.7)
	TLSKey     string // required for non-loopback binds (SPEC 8.7)
}

// Server is the aivault gateway process.
type Server struct {
	opts Options
}

// New returns a Server with the given options.
func New(opts Options) *Server { return &Server{opts: opts} }

// Run blocks serving the data and admin planes until shutdown (stub).
func (s *Server) Run() error { return errs.ErrNotImplemented }
