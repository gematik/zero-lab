package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(NonprodCmd)
	NonprodCmd.AddCommand(issueCmd)
}

var NonprodCmd = &cobra.Command{
	Use:   "non-prod",
	Short: "Non-production commands",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
