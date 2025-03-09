package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/gematik/zero-lab/go/pdp"
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
		fmt.Printf("Zero Policy Decision Point v%s\n", pdp.Version)
		configfile := viper.GetString("config_file")
		expanded, err := filepath.Abs(configfile)
		if err != nil {
			fmt.Printf("Error expanding config file: %s\n", err)
		} else {
			fmt.Println("Config file:", expanded)
		}

		fmt.Println("Working directory:", workdir)

	},
}
