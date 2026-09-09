// Package provider defines the built-in provider registry (SPEC 5).
package provider

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ZN9-KYANT/aivault/internal/vault"
)

// idPattern is the provider ID grammar (SPEC 3.2): [a-z0-9][a-z0-9-]{0,31}.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Provider describes one registry entry (SPEC 5).
type Provider struct {
	ID           string
	BaseURL      string
	Kinds        []vault.Kind
	OpenAICompat bool // wire-compatible with the /v1 data plane (SPEC 6.1)
}

// Builtin is the v1.0 registry. Anthropic and Gemini expose native,
// non-OpenAI-compatible APIs; translation shims arrive in v1.1 (SPEC 10).
var Builtin = []Provider{
	{ID: "openai", BaseURL: "https://api.openai.com/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "anthropic", BaseURL: "https://api.anthropic.com", Kinds: kinds(vault.KindAPIKey), OpenAICompat: false},
	{ID: "gemini", BaseURL: "https://generativelanguage.googleapis.com", Kinds: kinds(vault.KindAPIKey), OpenAICompat: false},
	{ID: "grok", BaseURL: "https://api.x.ai/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "deepseek", BaseURL: "https://api.deepseek.com/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "moonshot", BaseURL: "https://api.moonshot.ai/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "minimax", BaseURL: "https://api.minimax.io/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "nvidia", BaseURL: "https://integrate.api.nvidia.com/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
	{ID: "ollama-cloud", BaseURL: "https://ollama.com/v1", Kinds: kinds(vault.KindAPIKey), OpenAICompat: true},
}

func kinds(ks ...vault.Kind) []vault.Kind { return ks }

// BuiltinByID returns the built-in provider with the given ID.
func BuiltinByID(id string) (Provider, bool) {
	for _, p := range Builtin {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// ValidID reports whether id is a legal provider ID (SPEC 3.2).
func ValidID(id string) bool { return idPattern.MatchString(id) }

// SplitModel splits "provider/model" at the FIRST slash; the model part may
// itself contain slashes (e.g. openrouter/meta-llama/llama-3). Used for both
// data-plane routing (SPEC 6.1) and alias chain parsing (SPEC 5).
func SplitModel(raw string) (string, string, error) {
	i := strings.IndexByte(raw, '/')
	if i <= 0 || i == len(raw)-1 {
		return "", "", fmt.Errorf("invalid model %q", raw)
	}
	providerID, model := raw[:i], raw[i+1:]
	if !ValidID(providerID) {
		return "", "", fmt.Errorf("invalid provider namespace %q", providerID)
	}
	return providerID, model, nil
}
