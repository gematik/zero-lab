package main

import (
	"fmt"
	"log/slog"
	"os"

	console "github.com/phsym/console-slog"
	"github.com/spf13/cobra"

	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/gematik/zero-lab/go/ti/internal/connector"
	"github.com/gematik/zero-lab/go/ti/internal/epa"
	"github.com/gematik/zero-lab/go/ti/internal/pkcs12"
	"github.com/gematik/zero-lab/go/ti/internal/pki"
	"github.com/gematik/zero-lab/go/ti/internal/probe"
)

var verboseFlag bool

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ti",
		Short: "Telematik CLI tool",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			level := slog.LevelWarn
			if verboseFlag {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(console.NewHandler(os.Stderr, &console.HandlerOptions{
				Level:      level,
				TimeFormat: "2006-01-02 15:04:05",
			})))
		},
	}
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "enable debug logging")

	rootCmd.AddCommand(connector.NewCmd())
	rootCmd.AddCommand(epa.NewCmd())
	rootCmd.AddCommand(pkcs12.NewCmd())
	rootCmd.AddCommand(probe.NewCmd())
	rootCmd.AddCommand(pki.NewCmd())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(common.Version)
		},
	})

	return rootCmd
}

// Execute runs the root command, exiting with status 1 on error.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
