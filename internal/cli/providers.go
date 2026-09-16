package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/kdf"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/redact"
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
		Use:   "models [provider]",
		Short: "Fetch and list live /models — all enabled providers, or one (full catalog)",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runProvidersModels,
	}
	models.Flags().String("provider", "", "limit to one provider ID")

	test := &cobra.Command{
		Use:   "test <provider>",
		Short: "Test a provider's stored credential (GET /models)",
		Args:  cobra.ExactArgs(1),
		RunE:  runProvidersTest,
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

// providerClient fetches provider /models with a stored credential
// (OpenAI-compatible only, SPEC 5).
type providerClient struct{ client *http.Client }

func newProviderClient() *providerClient {
	return &providerClient{client: &http.Client{Timeout: 30 * time.Second}}
}

// probe fetches <base>/models and returns the model count and ids, or an
// error describing the upstream response.
func (pc *providerClient) probe(baseURL, cred string) (int, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return 0, nil, err
	}
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	resp, err := pc.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return resp.StatusCode, nil, probeUpstreamError(resp.StatusCode, cred, raw)
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&parsed); err != nil {
		return 0, nil, fmt.Errorf("HTTP 200 but unparseable: %w", err)
	}
	ids := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		ids = append(ids, m.ID)
	}
	return len(ids), ids, nil
}

// probeUpstreamError builds a redacted error for a failed /models probe: it
// caps and flattens the upstream body and scrubs credential-shaped strings
// (SPEC 8.4) so the provider's own error text reaches the user without
// leaking the stored key.
func probeUpstreamError(status int, cred string, body []byte) error {
	redact.Register([]string{cred})
	msg := strings.TrimSpace(redact.String(string(body)))
	if msg != "" {
		msg = strings.Join(strings.Fields(msg), " ")
		const max = 240
		if len(msg) > max {
			msg = msg[:max] + "…"
		}
		return fmt.Errorf("HTTP %d: %s", status, msg)
	}
	return fmt.Errorf("HTTP %d", status)
}

// providerTarget is one decrypted provider ready for a manual probe.
type providerTarget struct {
	id      string
	baseURL string
	cred    string
}

// providersTargets decrypts every enabled OpenAI-compatible provider with a
// stored key (or just `only`) into probe targets. The caller must Zeroize
// the returned passphrase.
func providersTargets(cmd *cobra.Command, only string) ([]providerTarget, []byte, error) {
	home := homeDir(cmd)
	cfg, err := loadVaultConfig(home)
	if err != nil {
		return nil, nil, err
	}
	pass, err := readAndVerifyPassphrase(home, cfg, "Master passphrase: ")
	if err != nil {
		return nil, nil, err
	}

	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return nil, nil, err
	}
	ids := make([]string, 0, len(meta.Providers))
	for id, pm := range meta.Providers {
		if !pm.Enabled || pm.Kind != string(vault.KindAPIKey) || !hasVaultFile(st, id) {
			continue
		}
		if p, isBuiltin := provider.BuiltinByID(id); isBuiltin && !p.OpenAICompat {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if only != "" {
		if !containsID(ids, only) {
			return nil, nil, fmt.Errorf("provider %q is not an enabled OpenAI-compatible provider with a stored key", only)
		}
		ids = []string{only}
	}

	out := make([]providerTarget, 0, len(ids))
	for _, id := range ids {
		p, err := st.Load(id, pass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", id, err)
			continue
		}
		if p.APIKey == nil || p.APIKey.BaseURL == "" {
			continue
		}
		out = append(out, providerTarget{id: id, baseURL: p.APIKey.BaseURL, cred: p.APIKey.Key})
	}
	return out, pass, nil
}

func containsID(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// runProvidersModels lists live /models per enabled OpenAI-compatible
// provider (SPEC 5: `providers models`). Without an argument it prints the
// summary table across all providers; with one argument (`providers models
// <id>`, or the legacy --provider flag) it lists that provider's FULL model
// catalog. Requires the master passphrase; no server involved.
func runProvidersModels(cmd *cobra.Command, args []string) error {
	only, _ := cmd.Flags().GetString("provider")
	if len(args) > 0 {
		if only != "" && only != args[0] {
			return fmt.Errorf("providers models: give the provider either as an argument or via --provider, not both")
		}
		only = args[0]
	}
	targets, pass, err := providersTargets(cmd, only)
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)
	if len(targets) == 0 {
		if only != "" {
			return fmt.Errorf("provider %q: no decrypted target (vault file missing?)", only)
		}
		fmt.Println("No enabled OpenAI-compatible providers with stored keys.")
		return nil
	}
	pc := newProviderClient()
	if only != "" {
		t := targets[0]
		_, list, err := pc.probe(t.baseURL, t.cred)
		if err != nil {
			return err
		}
		fmt.Printf("%s (%s): %d models\n", t.id, t.baseURL, len(list))
		for _, id := range list {
			fmt.Println(id)
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tMODELS\tFIRST MODELS")
	for _, t := range targets {
		_, list, err := pc.probe(t.baseURL, t.cred)
		if err != nil {
			fmt.Fprintf(w, "%s\tERROR\t%s\n", t.id, err.Error())
			continue
		}
		sample := ""
		if len(list) > 3 {
			sample = strings.Join(list[:3], ", ") + " …"
		} else {
			sample = strings.Join(list, ", ")
		}
		fmt.Fprintf(w, "%s\t%d\t%s\n", t.id, len(list), sample)
	}
	return w.Flush()
}

// runProvidersTest tests one provider's stored credential against its real
// endpoint (GET /models) and reports the outcome (SPEC 7).
func runProvidersTest(cmd *cobra.Command, args []string) error {
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
		fmt.Printf("%s: credential-free provider (base URL %s) — nothing to test\n", id, pm.BaseURL)
		return nil
	}
	if p, isBuiltin := provider.BuiltinByID(id); isBuiltin && !p.OpenAICompat {
		return fmt.Errorf("provider %q is not OpenAI wire-compatible; translation shims arrive in v1.1", id)
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
	p, err := st.Load(id, pass)
	if err != nil {
		return err
	}
	if p.APIKey == nil {
		return fmt.Errorf("vault: no API key payload for %q", id)
	}

	pc := newProviderClient()
	count, _, err := pc.probe(p.APIKey.BaseURL, p.APIKey.Key)
	outcome := fmt.Sprintf("%d", count)
	if err != nil {
		outcome = err.Error()
	}
	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventKeyUse, Provider: id, Outcome: "test/" + outcome}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	if err != nil {
		return fmt.Errorf("providers test %s: %w", id, err)
	}
	fmt.Printf("%s: OK — %s reachable, %d models\n", id, p.APIKey.BaseURL, count)
	return nil
}

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
