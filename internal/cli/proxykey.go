package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/proxykey"
)

func newProxyKeyCmd() *cobra.Command {
	pk := &cobra.Command{
		Use:   "proxykey",
		Short: "Manage downstream proxy keys (SPEC 4.4)",
	}

	create := &cobra.Command{
		Use:   "create --name <name>",
		Short: "Issue a new proxy key (plaintext shown exactly once)",
		RunE:  runProxyKeyCreate,
	}
	create.Flags().String("name", "", "human-readable key name (unique)")
	create.Flags().StringSlice("providers", nil, "allowed providers (empty = all registered providers)")
	create.Flags().Int("rpm", 0, "per-minute request limit (0 = unlimited; enforced in the hardening milestone)")
	create.Flags().Float64("max-usd/day", 0, "daily spend cap in USD (0 = none; enforced in the hardening milestone)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List proxy keys (hashes only, never plaintext)",
		RunE:  runProxyKeyList,
	}

	revoke := &cobra.Command{
		Use:   "revoke <id-or-name>",
		Short: "Revoke a proxy key (takes effect immediately, no unlock needed)",
		Args:  cobra.ExactArgs(1),
		RunE:  runProxyKeyRevoke,
	}

	pk.AddCommand(create, list, revoke)
	return pk
}

// runProxyKeyCreate issues a downstream key (SPEC 4.4): vk-<48 hex>, shown
// exactly once, stored as a SHA-256 digest in proxykeys.json. No unlock
// needed — the file holds hashes only.
func runProxyKeyCreate(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	name, _ := cmd.Flags().GetString("name")
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("proxykey create: --name is required")
	}
	providers, _ := cmd.Flags().GetStringSlice("providers")
	for _, id := range providers {
		if !provider.ValidID(id) {
			return fmt.Errorf("invalid provider ID %q (must match [a-z0-9][a-z0-9-]{0,31})", id)
		}
	}
	rpm, _ := cmd.Flags().GetInt("rpm")
	if rpm < 0 {
		return fmt.Errorf("proxykey create: --rpm must be >= 0")
	}
	maxUSD, _ := cmd.Flags().GetFloat64("max-usd/day")
	if maxUSD < 0 {
		return fmt.Errorf("proxykey create: --max-usd/day must be >= 0")
	}

	st := proxykey.NewStore(proxykey.DefaultPath(home))
	k, plaintext, err := proxykey.Generate()
	if err != nil {
		return err
	}
	k.Name = name
	k.Providers = providers
	k.RPM = rpm
	k.MaxUSDPerDay = maxUSD
	if err := st.Add(k); err != nil {
		return err
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventProxyKeyCreate, ProxyKeyID: k.ID, Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Created proxy key %q (id %s)\n", name, k.ID)
	fmt.Println(plaintext)
	fmt.Println("Shown only once — store it now.")
	return nil
}

func runProxyKeyList(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	keys, err := proxykey.NewStore(proxykey.DefaultPath(home)).List()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("No proxy keys yet — create one with: aivault proxykey create --name <name>")
		return nil
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].CreatedAt.Before(keys[j].CreatedAt) })
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tPROVIDERS\tRPM\tMAX USD/DAY\tREVOKED\tCREATED")
	for _, k := range keys {
		prov := strings.Join(k.Providers, ",")
		if prov == "" {
			prov = "*"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%.2f\t%v\t%s\n",
			k.ID, k.Name, prov, k.RPM, k.MaxUSDPerDay, k.Revoked, k.CreatedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

func runProxyKeyRevoke(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	k, err := proxykey.NewStore(proxykey.DefaultPath(home)).Revoke(args[0])
	if err != nil {
		return err
	}
	// No audit event exists for revoke in SPEC 4.5's list; proxykey.create is
	// audited at creation, and the proxykeys.json change is self-documenting.
	fmt.Printf("Revoked proxy key %q (id %s) — requests with it now fail immediately\n", k.Name, k.ID)
	return nil
}