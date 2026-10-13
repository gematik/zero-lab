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

	"github.com/gematik/zero-lab/go/epa"
	"github.com/joho/godotenv"
	"github.com/phsym/console-slog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verbose = false
var workdir = ""
var config *epa.Config = nil

var (
	rootCmd = &cobra.Command{
		Use:   "zero-epa",
		Short: "Zero Trust ePA Client",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logLevel := slog.LevelInfo
			if verbose {
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

			if workdir != "" {
				err := os.Chdir(workdir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to change working directory: %v\n", err)
					os.Exit(1)
				}
			}
			godotenv.Load()

			var err error
			config, err = epa.LoadConfigFile(viper.GetString("config_file"))
			if err != nil {
				slog.Error(fmt.Sprintf("load config file %q", viper.GetString("config_file")), "error", err)
				os.Exit(1)
			}
			slog.Debug("Loaded configuration", "file", viper.GetString("config_file"), "baseDir", config.BaseDir)
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
	persistendFlags.StringVarP(&workdir, "workdir", "w", "", "working directory")
	persistendFlags.BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	persistendFlags.StringP("config-file", "f", "zero-epa.yaml", "config file, relative to working directory")
	viper.BindPFlag("config_file", persistendFlags.Lookup("config-file"))
}
