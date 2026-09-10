package pki

import (
	"fmt"
	"strings"

	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

// newPKIStateCmd is the `ti pki state` parent.
func newPKIStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "state",
		Short: "Operate on the locally stored PKI data",
	}
	cmd.AddCommand(newPKIStateClearCmd())
	return cmd
}

// newPKIStateClearCmd deletes all `pki:`-prefixed entries from the shared
// state store, leaving the `epa:` half alone.
func newPKIStateClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Delete all locally stored PKI data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			st, err := common.LoadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()
			keys, err := st.Keys("pki:")
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				fmt.Println("No PKI state stored.")
				return nil
			}
			for _, k := range keys {
				if err := st.Delete(k); err != nil {
					return fmt.Errorf("deleting %q: %w", k, err)
				}
			}
			fmt.Printf("Cleared %d entries (%s).\n", len(keys), strings.Join(keys, ", "))
			return nil
		},
	}
}
