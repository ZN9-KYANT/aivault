package provider

import (
	"strings"
	"testing"

	"github.com/ZN9-KYANT/aivault/internal/vault"
)

func TestBuiltinRegistry(t *testing.T) {
	seen := make(map[string]bool, len(Builtin))
	for _, p := range Builtin {
		if !ValidID(p.ID) {
			t.Errorf("builtin ID %q fails the ID grammar", p.ID)
		}
		if seen[p.ID] {
			t.Errorf("duplicate builtin ID %q", p.ID)
		}
		seen[p.ID] = true
		if !strings.HasPrefix(p.BaseURL, "https://") {
			t.Errorf("%s: base URL %q is not https", p.ID, p.BaseURL)
		}
		if len(p.Kinds) == 0 {
			t.Errorf("%s: no kinds", p.ID)
		}
		for _, k := range p.Kinds {
			if k != vault.KindAPIKey && k != vault.KindNone {
				t.Errorf("%s: unsupported kind %q", p.ID, k)
			}
		}
	}
}

func TestBuiltinByID(t *testing.T) {
	if _, ok := BuiltinByID("openrouter"); !ok {
		t.Error("openrouter should be a builtin")
	}
	if _, ok := BuiltinByID("nope"); ok {
		t.Error("nope should not be a builtin")
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"a", "openai", "ollama-cloud", "0x-9"} {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"", "-x", "OpenAI", "a b", "a_b", strings.Repeat("a", 33)} {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}
