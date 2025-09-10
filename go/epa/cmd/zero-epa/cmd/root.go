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
