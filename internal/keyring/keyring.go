// Package keyring holds decrypted provider credentials in memory only
// (SPEC 2, 4.2): zeroized on lock, never written to disk.
package keyring

import (
	"sort"
	"sync"

	"github.com/ZN9-KYANT/aivault/internal/vault"
)

// Keyring is the in-memory credential store inside aivault serve.
type Keyring struct {
	mu       sync.RWMutex
	unlocked bool
	creds    map[string]*vault.Payload
}

// New returns an empty, locked keyring.
func New() *Keyring {
	return &Keyring{creds: make(map[string]*vault.Payload)}
}

// Unlock installs creds and marks the keyring unlocked. It takes ownership of
// the passed map (SPEC 4.2).
func (k *Keyring) Unlock(creds map[string]*vault.Payload) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.clearLocked()
	k.creds = creds
	k.unlocked = true
}

// Lock zeroizes all credentials and marks the keyring locked (SPEC 4.2).
func (k *Keyring) Lock() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.clearLocked()
	k.creds = make(map[string]*vault.Payload)
	k.unlocked = false
}

// Unlocked reports whether the keyring currently holds credentials.
func (k *Keyring) Unlocked() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.unlocked
}

// Get returns the payload for a provider.
func (k *Keyring) Get(provider string) (*vault.Payload, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	p, ok := k.creds[provider]
	return p, ok
}

// Providers lists the providers currently held, sorted by ID.
func (k *Keyring) Providers() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	ids := make([]string, 0, len(k.creds))
	for id := range k.creds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// clearLocked best-effort zeroizes credential material; k.mu must be held.
// Go strings are garbage-collected, so this is best-effort — hard
// zeroization and mlock are the memory-hygiene milestone (SPEC 8.3).
func (k *Keyring) clearLocked() {
	for id, p := range k.creds {
		if p != nil {
			if p.APIKey != nil {
				p.APIKey.Key = ""
				p.APIKey.Headers = nil
			}
			p.None = nil
		}
		delete(k.creds, id)
	}
}