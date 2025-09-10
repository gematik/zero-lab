package cmd

import (
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

func init() {
	rootCmd.AddCommand(configCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print the loaded configuration",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Config file: %s\n", viper.GetString("config_file"))
		config, err := epa.LoadConfigFile(viper.GetString("config_file"))
		if err != nil {
			slog.Error(fmt.Sprintf("load config file %q", viper.GetString("config_file")), "error", err)
			return
		}
		fmt.Printf("Base dir: %s\n", config.BaseDir)
		yaml.NewEncoder(cmd.OutOrStdout()).Encode(config)
	},
}
