package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newPKICacheCmd is the `ti pki cache` parent.
func newPKICacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Operate on the local PKI cache",
	}
	cmd.AddCommand(newPKICacheClearCmd())
	return cmd
}

// newPKICacheClearCmd deletes all `pki:`-prefixed entries from the unified
// state store. Replaces the previous `ti pki clear-cache` leaf.
func newPKICacheClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Delete all locally cached PKI data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			st, err := loadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()
			keys, err := st.Keys("pki:")
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				fmt.Println("Cache is already empty.")
				return nil
			}
			for _, k := range keys {
				if err := st.Delete(k); err != nil {
					return fmt.Errorf("deleting %q: %w", k, err)
				}
			}
			fmt.Printf("Cache cleared (%d entries: %s).\n", len(keys), strings.Join(keys, ", "))
			return nil
		},
	}
}
