package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/provider"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

func newAliasCmd() *cobra.Command {
	alias := &cobra.Command{
		Use:   "alias",
		Short: "Manage model aliases with failover chains (SPEC 5)",
	}

	create := &cobra.Command{
		Use:   "create <name> --chain <provider/model,provider/model,...>",
		Short: "Create an alias mapping a virtual model name to a failover chain",
		Args:  cobra.ExactArgs(1),
		RunE:  runAliasCreate,
	}
	create.Flags().String("chain", "", "comma-separated provider/model chain, tried in order (failover itself is gated by config.toml failover=true)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List aliases and their chains (no unlock needed)",
		RunE:  runAliasList,
	}

	remove := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an alias",
		Args:  cobra.ExactArgs(1),
		RunE:  runAliasRemove,
	}

	alias.AddCommand(create, list, remove)
	return alias
}

// runAliasCreate stores an alias chain in meta.json (SPEC 5). No unlock
// needed: aliases carry no secrets. Failover across the chain is gated by
// config.toml's failover flag (SPEC 6.1: configurable, default off).
func runAliasCreate(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	name := args[0]
	if !provider.ValidID(name) {
		return fmt.Errorf("invalid alias name %q (must match [a-z0-9][a-z0-9-]{0,31})", name)
	}
	chainRaw, _ := cmd.Flags().GetString("chain")
	if strings.TrimSpace(chainRaw) == "" {
		return fmt.Errorf("alias create: --chain is required")
	}
	if _, err := loadVaultConfig(home); err != nil {
		return err
	}

	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	if _, exists := meta.Aliases[name]; exists {
		return fmt.Errorf("alias %q already exists (aivault alias list)", name)
	}

	entries := strings.Split(chainRaw, ",")
	chain := make([]string, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		pid, _, err := provider.SplitModel(e)
		if err != nil {
			return fmt.Errorf("alias create: chain entry %q: %w", e, err)
		}
		if _, builtin := provider.BuiltinByID(pid); !builtin {
			if _, ok := meta.Providers[pid]; !ok {
				return fmt.Errorf("alias create: provider %q is neither builtin nor registered", pid)
			}
		}
		chain = append(chain, e)
	}
	if len(chain) == 0 {
		return fmt.Errorf("alias create: --chain must contain at least one provider/model entry")
	}
	if meta.Aliases == nil {
		meta.Aliases = make(map[string][]string)
	}
	meta.Aliases[name] = chain
	if err := st.SaveMeta(meta); err != nil {
		return fmt.Errorf("save meta: %w", err)
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: "alias.create", Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Created alias %s -> [%s]\n", name, strings.Join(chain, ", "))
	fmt.Println("Requests naming this model follow the chain; set failover = true in config.toml to enable retries.")
	return nil
}

func runAliasList(cmd *cobra.Command, _ []string) error {
	meta, err := vault.NewStore(homeDir(cmd)).LoadMeta()
	if err != nil {
		return err
	}
	if len(meta.Aliases) == 0 {
		fmt.Println("No aliases yet — create one with: aivault alias create <name> --chain <provider/model,...>")
		return nil
	}
	names := make([]string, 0, len(meta.Aliases))
	for name := range meta.Aliases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%s -> [%s]\n", name, strings.Join(meta.Aliases[name], ", "))
	}
	return nil
}

func runAliasRemove(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	if _, exists := meta.Aliases[args[0]]; !exists {
		return fmt.Errorf("no alias %q (aivault alias list)", args[0])
	}
	delete(meta.Aliases, args[0])
	if err := st.SaveMeta(meta); err != nil {
		return fmt.Errorf("save meta: %w", err)
	}
	fmt.Printf("Removed alias %s\n", args[0])
	return nil
}