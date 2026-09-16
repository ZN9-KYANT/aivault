package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/kdf"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

func newKeysCmd() *cobra.Command {
	keys := &cobra.Command{
		Use:   "keys",
		Short: "Manage provider API keys (SPEC 7)",
	}

	add := &cobra.Command{
		Use:   "add <provider>",
		Short: "Store an API key (via --key-stdin, hidden prompt, or $AIVAULT_<PROVIDER>_KEY; never as an argument)",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeysAdd,
	}
	add.Flags().Bool("key-stdin", false, "read the key from stdin (consumes all of stdin)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List providers from meta.json (no unlock needed)",
		RunE:  runKeysList,
	}

	show := &cobra.Command{
		Use:   "show <provider>",
		Short: "Show a stored key (hint by default; --reveal prints the full key)",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeysShow,
	}
	show.Flags().Bool("reveal", false, "decrypt the vault and print the full key (SPEC 7)")

	remove := &cobra.Command{
		Use:   "remove <provider>",
		Short: "Remove a provider's stored key (asks for confirmation)",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeysRemove,
	}

	rotate := &cobra.Command{
		Use:   "rotate <provider>",
		Short: "Replace a provider's key (via --key-stdin or hidden prompt)",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeysRotate,
	}
	rotate.Flags().Bool("key-stdin", false, "read the new key from stdin (consumes all of stdin)")

	keys.AddCommand(add, list, show, remove, rotate)
	return keys
}

func runKeysAdd(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	id := args[0]

	cfg, err := loadVaultConfig(home)
	if err != nil {
		return err
	}
	if !provider.ValidID(id) {
		return fmt.Errorf("invalid provider ID %q (must match [a-z0-9][a-z0-9-]{0,31})", id)
	}

	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}

	// Resolve the base URL: builtin registry default, or the custom one
	// recorded in meta.json by providers add (SPEC 5).
	var baseURL string
	if p, ok := provider.BuiltinByID(id); ok {
		baseURL = p.BaseURL
	}
	if pm, ok := meta.Providers[id]; ok && pm.BaseURL != "" {
		baseURL = pm.BaseURL
	}
	if baseURL == "" {
		return fmt.Errorf("unknown provider %q — not a builtin and not added via providers add", id)
	}

	key, err := readProviderKey(cmd, id)
	if err != nil {
		return err
	}
	defer kdf.Zeroize(key)
	if len(key) == 0 {
		return fmt.Errorf("empty API key")
	}

	pass, err := readAndVerifyPassphrase(home, cfg, "Master passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)

	payload := &vault.Payload{
		Version:  vault.PayloadVersion,
		Provider: id,
		Kind:     vault.KindAPIKey,
		APIKey: &vault.APIKey{
			Key:     string(key),
			BaseURL: baseURL,
		},
	}
	if err := st.Save(id, pass, payload); err != nil {
		return fmt.Errorf("store key: %w", err)
	}

	now := time.Now().UTC()
	pm := meta.Providers[id]
	pm.Kind = string(vault.KindAPIKey)
	pm.BaseURL = baseURL
	pm.KeyHint = vault.KeyHint(string(key))
	pm.Enabled = true
	pm.UpdatedAt = now
	if pm.CreatedAt.IsZero() {
		pm.CreatedAt = now
	}
	meta.Providers[id] = pm
	if err := st.SaveMeta(meta); err != nil {
		return fmt.Errorf("save meta: %w", err)
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventKeyAdd, Provider: id, Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Stored API key for %s (%s)\n", id, vault.KeyHint(string(key)))
	return nil
}

func runKeysShow(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	id := args[0]
	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	pm, ok := meta.Providers[id]
	if !ok {
		return fmt.Errorf("no credential stored for %q (see aivault keys list)", id)
	}
	if pm.Kind == string(vault.KindNone) {
		fmt.Printf("%s: no API key (credential-free provider, base URL %s)\n", id, pm.BaseURL)
		return nil
	}

	// The hint lives in plaintext meta.json (SPEC 3.3) — no unlock needed.
	reveal, _ := cmd.Flags().GetBool("reveal")
	if !reveal && pm.KeyHint != "" {
		fmt.Printf("%s: %s\n", id, pm.KeyHint)
		return nil
	}

	// --reveal (or a missing hint) needs the master passphrase (SPEC 4.1).
	cfg, err := loadVaultConfig(home)
	if err != nil {
		return err
	}
	pass, err := readAndVerifyPassphrase(home, cfg, "Master passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)
	p, err := st.Load(id, pass)
	if err != nil {
		return err
	}
	if p.APIKey == nil {
		return fmt.Errorf("vault: no API key payload for %q", id)
	}
	if !reveal {
		fmt.Printf("%s: %s\n", id, vault.KeyHint(p.APIKey.Key))
		return nil
	}
	fmt.Printf("%s: %s\n", id, p.APIKey.Key)
	return nil
}

// runKeysRemove deletes the encrypted vault file (if any) and the meta.json
// entry. It deliberately does not require the passphrase: removing a file is
// equivalent to an rm, which is always possible for the user of the home
// dir — the vault protects confidentiality, not availability (SPEC 8.2).
func runKeysRemove(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	id := args[0]
	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	pm, inMeta := meta.Providers[id]
	hasFile := hasVaultFile(st, id)
	if !inMeta && !hasFile {
		return fmt.Errorf("no credential stored for %q (see aivault keys list)", id)
	}

	what := fmt.Sprintf("stored key for %s", id)
	if _, isBuiltin := provider.BuiltinByID(id); !isBuiltin {
		what = fmt.Sprintf("stored key and registration for %s", id)
	}
	if inMeta && pm.Kind == string(vault.KindNone) && !hasFile {
		what = fmt.Sprintf("credential-free provider registration %s", id)
	}
	ans, err := readLine(fmt.Sprintf("Remove %s? (y/N) ", what))
	if err != nil {
		return err
	}
	if t := strings.ToLower(strings.TrimSpace(ans)); t != "y" && t != "yes" {
		fmt.Println("aborted — nothing removed")
		return nil
	}

	// Remove the encrypted file first, then the index entry (SPEC 8.2).
	if hasFile {
		if err := st.DeleteProvider(id); err != nil {
			return fmt.Errorf("remove vault file: %w", err)
		}
	}
	if inMeta {
		delete(meta.Providers, id)
		if err := st.SaveMeta(meta); err != nil {
			return fmt.Errorf("save meta: %w", err)
		}
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventKeyRemove, Provider: id, Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Removed %s\n", what)
	return nil
}

// runKeysRotate replaces a provider's API key, preserving the payload's base
// URL and custom headers (SPEC 3.4, 7).
func runKeysRotate(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	id := args[0]
	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	pm, ok := meta.Providers[id]
	if !ok {
		return fmt.Errorf("no credential stored for %q — use aivault keys add", id)
	}
	if pm.Kind == string(vault.KindNone) {
		return fmt.Errorf("provider %q is credential-free (kind none); nothing to rotate", id)
	}

	key, err := readProviderKey(cmd, id)
	if err != nil {
		return err
	}
	defer kdf.Zeroize(key)
	if len(key) == 0 {
		return fmt.Errorf("empty API key")
	}

	cfg, err := loadVaultConfig(home)
	if err != nil {
		return err
	}
	pass, err := readAndVerifyPassphrase(home, cfg, "Master passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)

	old, err := st.Load(id, pass)
	if err != nil {
		return fmt.Errorf("load existing key: %w", err)
	}
	if old.APIKey == nil {
		return fmt.Errorf("vault: payload for %q has no API key", id)
	}
	old.APIKey.Key = string(key)
	if err := st.Save(id, pass, old); err != nil {
		return fmt.Errorf("store key: %w", err)
	}

	pm.KeyHint = vault.KeyHint(string(key))
	pm.UpdatedAt = time.Now().UTC()
	meta.Providers[id] = pm
	if err := st.SaveMeta(meta); err != nil {
		return fmt.Errorf("save meta: %w", err)
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventKeyRotate, Provider: id, Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Rotated API key for %s (%s)\n", id, vault.KeyHint(string(key)))
	return nil
}

// readProviderKey reads the provider API key per the SPEC 8 security rules:
// --key-stdin first, then $AIVAULT_<PROVIDER>_KEY (with warning), then a
// hidden prompt.
func readProviderKey(cmd *cobra.Command, id string) ([]byte, error) {
	if keyStdin, _ := cmd.Flags().GetBool("key-stdin"); keyStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read key from stdin: %w", err)
		}
		return bytes.TrimSpace(b), nil
	}
	env := fmt.Sprintf("AIVAULT_%s_KEY", strings.ToUpper(strings.ReplaceAll(id, "-", "_")))
	if v := os.Getenv(env); v != "" {
		fmt.Fprintf(os.Stderr, "warning: using API key from %s environment variable\n", env)
		return []byte(v), nil
	}
	key, err := readSecret(fmt.Sprintf("API key for %s: ", id))
	if err != nil {
		return nil, err
	}
	return key, nil
}

// hasVaultFile reports whether vault/<provider>.json.age exists.
func hasVaultFile(st *vault.Store, id string) bool {
	_, err := os.Stat(st.ProviderPath(id))
	return err == nil
}

func runKeysList(cmd *cobra.Command, _ []string) error {
	st := vault.NewStore(homeDir(cmd))
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	if len(meta.Providers) == 0 {
		fmt.Println("No providers stored yet — add one with: aivault keys add <provider>")
		return nil
	}

	ids := make([]string, 0, len(meta.Providers))
	for id := range meta.Providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tKIND\tBASE URL\tKEY HINT\tENABLED\tUPDATED")
	for _, id := range ids {
		pm := meta.Providers[id]
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\n",
			id, pm.Kind, pm.BaseURL, pm.KeyHint, pm.Enabled, pm.UpdatedAt.Format(time.RFC3339))
	}
	return w.Flush()
}
