package main

import (
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/pkg/prettylog"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "zero",
	Short: "Zero Trust CLI",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func main() {
	if os.Getenv("PRETTY_LOGS") != "false" {
		logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
		slog.SetDefault(logger)
	}
	rootCmd.Execute()
}
