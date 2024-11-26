package cmd

import (
	"fmt"

	"github.com/gematik/zero-lab/go/libzero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Zero v%s\n", libzero.Version)
		fmt.Printf("Config file: %s\n", viper.GetString("config_file"))
	},
}
