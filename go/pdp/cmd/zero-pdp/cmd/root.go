// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/phsym/console-slog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "zero-pdp",
		Short: "Zero Trust Policy Decision Point",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			workdir := viper.GetString("workdir")
			if workdir != "" {
				err := os.Chdir(workdir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to change working directory: %v\n", err)
					os.Exit(1)
				}
			}
			godotenv.Load()

			logLevel := slog.LevelInfo
			if viper.GetBool("verbose") {
				logLevel = slog.LevelDebug
			}
			if os.Getenv("PRETTY_LOGS") != "false" {
				logger := slog.New(
					console.NewHandler(os.Stderr, &console.HandlerOptions{Level: logLevel}),
				)
				slog.SetDefault(logger)
			} else {
				slog.SetLogLoggerLevel(logLevel)
			}

		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("PDP")
	persistendFlags := rootCmd.PersistentFlags()
	persistendFlags.StringP("workdir", "w", "", "working directory")
	persistendFlags.BoolP("verbose", "v", false, "verbose output")
	persistendFlags.StringP("config-file", "f", "pdp.yaml", "config file (default is pdp.yaml)")
	viper.BindPFlag("workdir", persistendFlags.Lookup("workdir"))
	viper.BindPFlag("verbose", persistendFlags.Lookup("verbose"))
	viper.BindPFlag("config_file", persistendFlags.Lookup("config-file"))
}

// Expand ~ to $HOME
func expandHome(path string) string {
	if strings.HasPrefix(path, "~") {
		home, _ := os.UserHomeDir()
		path = strings.Replace(path, "~", home, 1)
	}
	return path
}
