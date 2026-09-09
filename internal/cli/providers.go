package cli

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/errs"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

func newProvidersCmd() *cobra.Command {
	providers := &cobra.Command{
		Use:   "providers",
		Short: "Inspect and manage providers (SPEC 5, 7)",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List registered providers from meta.json (no unlock needed)",
		RunE:  runProvidersList,
	}

	models := &cobra.Command{
		Use:   "models",
		Short: "List cached /models per provider",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("providers models: %w", errs.ErrNotImplemented)
		},
	}

	test := &cobra.Command{
		Use:   "test <provider>",
		Short: "Test a provider's stored credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("providers test: %w", errs.ErrNotImplemented)
		},
	}

	add := &cobra.Command{
		Use:   "add <id> --base-url <url>",
		Short: "Register a custom provider (builtin IDs are reserved; no unlock needed)",
		Args:  cobra.ExactArgs(1),
		RunE:  runProvidersAdd,
	}
	add.Flags().String("base-url", "", "provider base URL (absolute http/https)")

	providers.AddCommand(list, models, test, add)
	return providers
}

// runProvidersAdd registers a custom provider in meta.json (SPEC 5): a
// user-defined base URL served through the gateway. Builtin IDs are reserved.
// Registration stores no secret; keys arrive later via aivault keys add (kind
// apikey) or never for credential-free local servers (kind none, SPEC 3.4).
func runProvidersAdd(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	id := args[0]
	baseURL, _ := cmd.Flags().GetString("base-url")
	if baseURL == "" {
		return fmt.Errorf("providers add: --base-url is required")
	}
	if !provider.ValidID(id) {
		return fmt.Errorf("invalid provider ID %q (must match [a-z0-9][a-z0-9-]{0,31})", id)
	}
	if _, isBuiltin := provider.BuiltinByID(id); isBuiltin {
		return fmt.Errorf("provider %q is built-in and cannot be re-registered", id)
	}
	if err := validateBaseURL(baseURL); err != nil {
		return fmt.Errorf("providers add: %w", err)
	}
	if _, err := loadVaultConfig(home); err != nil {
		return err
	}

	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	if _, exists := meta.Providers[id]; exists {
		return fmt.Errorf("provider %q is already registered (aivault keys list)", id)
	}

	now := time.Now().UTC()
	meta.Providers[id] = vault.ProviderMeta{
		Kind:      string(vault.KindNone),
		BaseURL:   baseURL,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.SaveMeta(meta); err != nil {
		return fmt.Errorf("save meta: %w", err)
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventProviderAdd, Provider: id, Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Registered custom provider %s -> %s\n", id, baseURL)
	fmt.Printf("Add a key with: aivault keys add %s (skip for credential-free local servers)\n", id)
	return nil
}

func runProvidersList(cmd *cobra.Command, _ []string) error {
	st := vault.NewStore(homeDir(cmd))
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	if len(meta.Providers) == 0 {
		fmt.Println("No providers registered yet — add one with: aivault providers add <id> --base-url <url>")
		return nil
	}

	ids := make([]string, 0, len(meta.Providers))
	for id := range meta.Providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tKIND\tBASE URL\tENABLED\tUPDATED")
	for _, id := range ids {
		pm := meta.Providers[id]
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n",
			id, pm.Kind, pm.BaseURL, pm.Enabled, pm.UpdatedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

// validateBaseURL requires an absolute http(s) URL with a host (SPEC 5).
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid base URL %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid base URL %q: missing host", raw)
	}
	return nil
}