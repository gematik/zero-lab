package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
	"github.com/phsym/console-slog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verbose = false
var workdir = ""

var (
	rootCmd = &cobra.Command{
		Use:   "zero-epa",
		Short: "Zero Trust ePA Client",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if workdir != "" {
				err := os.Chdir(workdir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to change working directory: %v\n", err)
					os.Exit(1)
				}
			}
			godotenv.Load()

			logLevel := slog.LevelInfo
			if verbose {
				logLevel = slog.LevelDebug
			}
			if os.Getenv("PRETTY_LOGS") != "false" {
				logger := slog.New(
					console.NewHandler(os.Stderr, &console.HandlerOptions{Level: slog.LevelDebug}),
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
	persistendFlags.StringVarP(&workdir, "workdir", "w", "", "working directory")
	persistendFlags.BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	persistendFlags.StringP("config-file", "f", "zero-epa.yaml", "config file, relative to working directory")
	viper.BindPFlag("config_file", persistendFlags.Lookup("config-file"))
}
