package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/redact"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read the append-only audit log (SPEC 4.5)",
		RunE:  runAudit,
	}
	cmd.Flags().Int("tail", 50, "show the last N entries")
	cmd.Flags().Bool("json", false, "print raw JSONL entries")
	return cmd
}

func runAudit(cmd *cobra.Command, _ []string) error {
	n, _ := cmd.Flags().GetInt("tail")
	if n < 0 {
		n = 50
	}
	asJSON, _ := cmd.Flags().GetBool("json")

	entries, err := readAuditTail(homeDir(cmd), n)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("Audit log is empty.")
		return nil
	}

	// Defensive pass: nothing in the log should ever contain a secret, but the
	// display path still runs the redaction filter (SPEC 8.4).
	if asJSON {
		for _, e := range entries {
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Println(redact.String(string(data)))
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tEVENT\tPROVIDER\tPROXY KEY\tOUTCOME")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp.Format(time.RFC3339), e.Event, e.Provider, e.ProxyKeyID,
			strings.TrimSpace(redact.String(e.Outcome)))
	}
	return w.Flush()
}

// readAuditTail reads the last n entries from <home>/audit.log.
func readAuditTail(home string, n int) ([]audit.Entry, error) {
	return audit.Tail(auditPath(home), n)
}
