package cmd

import (
	"fmt"

	"github.com/gematik/zero-lab/go/pdp/oauth2server"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(secretHashCmd)
}

var secretHashCmd = &cobra.Command{
	Use:   "secret-hash [secret]",
	Short: "Hashes the given secret",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		secret := args[0]
		hashed, err := oauth2server.HashSecret(secret)
		cobra.CheckErr(err)
		fmt.Println(hashed)
	},
}
