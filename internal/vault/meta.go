package vault

import "time"

// PayloadVersion is the current vault payload and meta schema version (SPEC 3).
const PayloadVersion = 1

// Meta is the plaintext index ~/.aivault/meta.json (SPEC 3.3). It contains no
// secrets — only hints, so `aivault keys list` works without unlocking.
type Meta struct {
	Version   int                     `json:"version"`
	Providers map[string]ProviderMeta `json:"providers"`
}

// ProviderMeta is one provider's entry in meta.json (SPEC 3.3).
type ProviderMeta struct {
	Kind      string    `json:"kind"`
	BaseURL   string    `json:"base_url"`
	KeyHint   string    `json:"key_hint,omitempty"` // first-3/last-4 characters only
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}