package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/gematik/zero-lab/go/kon"
	console "github.com/phsym/console-slog"
	"github.com/spf13/cobra"
)

var (
	konFlag     string
	verboseFlag bool
)

func main() {
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
				TimeFormat: time.TimeOnly,
			})))
		},
	}
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "enable debug logging")

	konCmd := &cobra.Command{
		Use:   "kon",
		Short: "Konnektor commands",
		Long:  "Commands for interacting with the Gematik Konnektor.\n\nSpecify a .kon configuration with -k/--kon or DOTKON_FILE env var.\nThe name is resolved as: exact path, <name>.kon in current dir, then $XDG_CONFIG_HOME/telematik/kon/",
	}
	konCmd.PersistentFlags().StringVarP(&konFlag, "kon", "k", "", "name or path of .kon configuration file (env: DOTKON_FILE)")
	konCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "text", "output format: text, json")

	konCmd.AddCommand(newGetCmd())
	konCmd.AddCommand(newDescribeCmd())
	konCmd.AddCommand(newVerifyCmd())
	konCmd.AddCommand(newChangeCmd())

	rootCmd.AddCommand(konCmd)
	rootCmd.AddCommand(newPKCS12Cmd())
	rootCmd.AddCommand(newProbeCmd())
	rootCmd.AddCommand(newPKICmd())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(Version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadDotkon() (*kon.Dotkon, error) {
	name := konFlag
	if name == "" {
		name = os.Getenv("DOTKON_FILE")
	}
	if name == "" {
		name = "default"
	}

	path, err := resolveKonFile(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return kon.ParseDotkon(data)
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	s := string(data) + "\n"
	if isTerminal() {
		return quick.Highlight(os.Stdout, s, "json", "terminal256", "monokai")
	}
	fmt.Print(s)
	return nil
}

func resolveKonFile(name string) (string, error) {
	// Expand ~ to home directory
	if strings.HasPrefix(name, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolving home directory: %w", err)
		}
		name = filepath.Join(home, name[2:])
	}

	// Full paths (absolute or with directory separators): only check as-is and with .kon extension
	if filepath.IsAbs(name) || strings.Contains(name, string(filepath.Separator)) {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
		withExt := name + ".kon"
		if _, err := os.Stat(withExt); err == nil {
			return withExt, nil
		}
		return "", fmt.Errorf("configuration file not found: %s", name)
	}

	// Short name: search current directory, then XDG config directory

	// 1. Try as-is in current directory
	if _, err := os.Stat(name); err == nil {
		return name, nil
	}

	// 2. Try with .kon extension in current directory
	withExt := name + ".kon"
	if _, err := os.Stat(withExt); err == nil {
		return withExt, nil
	}

	// 3. Try XDG config directory: $XDG_CONFIG_HOME/telematik/kon/<name>.kon
	xdgPath := filepath.Join(xdg.ConfigHome, "telematik", "kon", name+".kon")
	if _, err := os.Stat(xdgPath); err == nil {
		return xdgPath, nil
	}
	xdgPathExact := filepath.Join(xdg.ConfigHome, "telematik", "kon", name)
	if _, err := os.Stat(xdgPathExact); err == nil {
		return xdgPathExact, nil
	}

	return "", fmt.Errorf("configuration %q not found (searched current directory and %s/telematik/kon/)",
		name, xdg.ConfigHome)
}
