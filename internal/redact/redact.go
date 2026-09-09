// Package redact scrubs credential-shaped strings from log sinks and error
// text (SPEC 8.4): Bearer tokens, sk-*/vk-*/nvapi-*/AIza-style keys, plus any
// secret values registered at runtime (e.g. decrypted provider keys).
package redact

import (
	"regexp"
	"strings"
	"sync"
)

// Credential-shaped patterns. Each requires enough entropy that matching
// never eats ordinary prose.
var patterns = []struct {
	re  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`Bearer[ ]+[A-Za-z0-9._~+/-]+=*`), "Bearer [REDACTED]"},
	{regexp.MustCompile(`\bvk-[0-9a-f]{48}\b`), "vk-[REDACTED]"},
	{regexp.MustCompile(`\bnvapi-[A-Za-z0-9_-]{20,}\b`), "nvapi-[REDACTED]"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`), "sk-[REDACTED]"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`), "AIza[REDACTED]"},
	{regexp.MustCompile(`\bgsk_[A-Za-z0-9]{20,}\b`), "gsk_[REDACTED]"},
	{regexp.MustCompile(`\bxai-[A-Za-z0-9_-]{20,}\b`), "xai-[REDACTED]"},
}

var (
	mu      sync.RWMutex
	secrets = map[string]struct{}{}
)

// Register adds literal secret values (e.g. decrypted provider keys) to the
// redaction set. The server calls this after unlock so any error path that
// echoes request data cannot leak a live credential (SPEC 8.4).
func Register(values []string) {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range values {
		if len(s) >= 8 {
			secrets[s] = struct{}{}
		}
	}
}

// Reset drops all registered literal secrets (lock, shutdown, tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	secrets = map[string]struct{}{}
}

// String returns s with credential-shaped substrings replaced.
func String(s string) string {
	if s == "" {
		return s
	}
	for _, p := range patterns {
		s = p.re.ReplaceAllLiteralString(s, p.rep)
	}
	mu.RLock()
	defer mu.RUnlock()
	for secret := range secrets {
		s = strings.ReplaceAll(s, secret, "[REDACTED]")
	}
	return s
}