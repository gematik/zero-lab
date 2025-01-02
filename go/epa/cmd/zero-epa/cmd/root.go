package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"time"

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
	persistendFlags.StringVarP(&workdir, "workdir", "w", "", "working directory")
	persistendFlags.BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	persistendFlags.StringP("config-file", "f", "zero-epa.yaml", "config file, relative to working directory")
	viper.BindPFlag("config_file", persistendFlags.Lookup("config-file"))

	persistendFlags.StringP("vsdm-hmac-key", "", "", "VSDM HMAC Key")
	viper.BindPFlag("vsdm-hmac-key", persistendFlags.Lookup("vsdm-hmac-key"))
	viper.BindEnv("vsdm-hmac-key", "VSDM_HMAC_KEY")

	persistendFlags.StringP("vsdm-hmac-kid", "", "", "VSDM HMAC Key ID")
	viper.BindPFlag("vsdm-hmac-kid", persistendFlags.Lookup("vsdm-hmac-kid"))
	viper.BindEnv("vsdm-hmac-kid", "VSDM_HMAC_KID")

	persistendFlags.StringP("authn-private-key-path", "", "", "Path to SMC-B private key")
	viper.BindPFlag("authn-private-key-path", persistendFlags.Lookup("authn-private-key-path"))
	viper.BindEnv("authn-private-key-path", "AUTHN_PRIVATE_KEY_PATH")

	persistendFlags.StringP("authn-cert-path", "", "", "Path to SMC-B certificate")
	viper.BindPFlag("authn-cert-path", persistendFlags.Lookup("authn-cert-path"))
	viper.BindEnv("authn-cert-path", "AUTHN_CERT_PATH")

	persistendFlags.DurationP("timeout", "t", 10*time.Second, "Timeout for requests as duration")
	viper.BindPFlag("timeout", persistendFlags.Lookup("timeout"))
	viper.BindEnv("timeout", "TIMEOUT")

	persistendFlags.StringP("env", "e", "dev", "ePA Environment (dev, ref, test, prod)")
	viper.BindPFlag("env", persistendFlags.Lookup("env"))
	viper.BindEnv("env", "EPA_ENV")

}
