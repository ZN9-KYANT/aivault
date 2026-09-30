// Package egress pins upstream connections to an allowlist of provider
// hosts (learned from pi-llm-gateway): provider adapters may only dial
// hosts whose base URLs are registered in the vault, so a tampered config
// or DNS drift cannot exfiltrate live credentials to a rogue server. The
// guard hooks the dial layer, which also re-validates HTTP redirects.
package egress

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

var (
	mu      sync.RWMutex
	allow   map[string]struct{}
	enabled bool
)

// SetAllowlist restricts upstream dials to the given hostnames (lowercased,
// port-agnostic). Entries may be plain hostnames or host:port (the hostname
// is matched port-agnostically). An empty list disables the guard entirely.
func SetAllowlist(hosts []string) error {
	m := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return fmt.Errorf("egress: empty host in allowlist")
		}
		if host, port, err := net.SplitHostPort(h); err == nil && host != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("egress: invalid host %q", h)
			}
			m[strings.ToLower(host)] = struct{}{} // port-agnostic hostname match
			m[strings.ToLower(h)] = struct{}{}    // exact host:port also matches
			continue
		}
		m[strings.ToLower(strings.TrimSuffix(h, "."))] = struct{}{}
	}
	mu.Lock()
	defer mu.Unlock()
	allow, enabled = m, len(m) > 0
	return nil
}

// Enabled reports whether the guard currently drops non-allowlisted hosts.
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabled
}

// Hosts returns the current allowlist (sorted order is not guaranteed).
func Hosts() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(allow))
	for h := range allow {
		out = append(out, h)
	}
	return out
}

// Guarded wraps a base dialer so every upstream dial is validated against
// the allowlist (pass-through when disabled). Redirects are re-validated
// because each dial goes through this function again.
func Guarded(base func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.RLock()
		guarded := enabled
		allowed := allow
		mu.RUnlock()
		if guarded {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("egress: malformed address %q", addr)
			}
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if _, ok := allowed[host]; !ok {
				return nil, fmt.Errorf("egress: refusing connection to non-allowlisted upstream host %q", host)
			}
		}
		return base(ctx, network, addr)
	}
}
