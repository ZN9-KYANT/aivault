package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/errs"
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
		Short: "Show the stored key (hint by default; requires unlock)",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys show: %w", errs.ErrNotImplemented)
		},
	}
	show.Flags().Bool("reveal", false, "print the full key instead of the hint")

	remove := &cobra.Command{
		Use:   "remove <provider>",
		Short: "Remove a provider's stored key",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys remove: %w", errs.ErrNotImplemented)
		},
	}

	rotate := &cobra.Command{
		Use:   "rotate <provider>",
		Short: "Replace a provider's key (via --key-stdin or hidden prompt)",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys rotate: %w", errs.ErrNotImplemented)
		},
	}
	rotate.Flags().Bool("key-stdin", false, "read the new key from stdin (consumes all of stdin)")

	keys.AddCommand(add, list, show, remove, rotate)
	return keys
}

func runKeysAdd(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	id := args[0]

	cfg, err := config.Load(config.Path(home))
	if err != nil {
		return fmt.Errorf("vault not initialized at %s (run aivault init first): %w", home, err)
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

	pass, err := readSecret("Master passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)
	if err := cfg.VerifyPassphrase(pass); err != nil {
		_ = audit.Log(auditPath(home), audit.Entry{Event: audit.EventAuthFail, Outcome: "wrong-passphrase"})
		if errors.Is(err, kdf.ErrWrongPassphrase) {
			return fmt.Errorf("incorrect passphrase")
		}
		return fmt.Errorf("verify passphrase: %w", err)
	}

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
