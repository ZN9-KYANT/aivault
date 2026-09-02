// Package vault implements the on-disk credential vault: one age-encrypted
// JSON file per provider plus the plaintext metadata index (SPEC 3).
package vault

// Kind is the credential kind stored for a provider (SPEC 3.4).
type Kind string

// Supported credential kinds. OAuth is intentionally excluded (SPEC 1):
// the vault stores static API keys only.
const (
	KindAPIKey Kind = "apikey"
	KindNone   Kind = "none"
)

// APIKey is the apikey credential payload (SPEC 3.4).
type APIKey struct {
	Key     string            `json:"key"`
	BaseURL string            `json:"base_url"`
	Headers map[string]string `json:"headers,omitempty"`
}

// NoneCred describes a credential-free local server (SPEC 3.4), reachable
// via custom providers.
type NoneCred struct {
	BaseURL string `json:"base_url"`
}

// Payload is the decrypted JSON document inside vault/<provider>.json.age
// (SPEC 3.4). Exactly one of APIKey/None is populated per Kind.
type Payload struct {
	Version  int       `json:"version"`
	Provider string    `json:"provider"`
	Kind     Kind      `json:"kind"`
	APIKey   *APIKey   `json:"apikey,omitempty"`
	None     *NoneCred `json:"none,omitempty"`
}
