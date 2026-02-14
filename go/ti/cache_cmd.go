package main

import "github.com/spf13/cobra"

func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the local SOAP response cache",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Delete the cache database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return clearCache()
		},
	})

	return cmd
}
