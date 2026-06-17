package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/gematik/zero-lab/go/kon"
	console "github.com/phsym/console-slog"
	"github.com/spf13/cobra"
)

var (
	connectorConfigFlag string
	verboseFlag         bool
)

const connectorConfigEnv = "TI_CONNECTOR_CONFIG"

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
				TimeFormat: "2006-01-02 15:04:05",
			})))
		},
	}
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "enable debug logging")

	connectorCmd := &cobra.Command{
		Use:   "connector",
		Short: "Connector (Konnektor) commands",
		Long: "Commands for interacting with the Gematik Konnektor.\n\n" +
			"Select a configuration with -c/--connector-config, the " + connectorConfigEnv + " env var,\n" +
			"or `ti connector use <name>` to make a selection sticky.\n\n" +
			"Names resolve as: exact path, <name>.kon in current dir, then $XDG_CONFIG_HOME/telematik/connectors/.",
	}
	connectorCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "text", "output format: text, json")

	connectorCmd.AddCommand(newGetCmd())
	connectorCmd.AddCommand(newDescribeCmd())
	connectorCmd.AddCommand(newVerifyCmd())
	connectorCmd.AddCommand(newChangeCmd())
	connectorCmd.AddCommand(newConnectorConfigsCmd())
	connectorCmd.AddCommand(newConnectorUseCmd())

	rootCmd.AddCommand(connectorCmd)
	rootCmd.AddCommand(newEpaCmd())
	rootCmd.AddCommand(newPKCS12Cmd())
	rootCmd.AddCommand(newProbeCmd())
	rootCmd.AddCommand(newPKICmd())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(resolveVersion())
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func addConnectorConfigFlag(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&connectorConfigFlag, "connector-config", "c", "",
		"name or path of .kon configuration file (env: "+connectorConfigEnv+")")
	cmd.RegisterFlagCompletionFunc("connector-config", completeConnectorConfigNames)
}

func completeConnectorConfigNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	configs := collectConnectorConfigs()
	names := make([]string, 0, len(configs))
	for _, c := range configs {
		names = append(names, c.Name)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func loadConnectorConfig() (*kon.Dotkon, error) {
	name := connectorConfigFlag
	source := "flag"
	if name == "" {
		name = os.Getenv(connectorConfigEnv)
		source = "env " + connectorConfigEnv
	}
	if name == "" {
		if active, err := readActiveConnector(); err == nil && active != "" {
			name = active
			source = "active file"
		}
	}
	if name == "" {
		name = "default"
		source = "default"
	}

	path, err := resolveConnectorConfigFile(name)
	if err != nil {
		if source == "active file" {
			return nil, fmt.Errorf("%w\n\nthe active connector points at %q which no longer resolves; run `ti connector use <name>` to pick another, or `ti connector configs` to list available configs", err, name)
		}
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return kon.ParseDotkon(data)
}

func activeConnectorFile() string {
	return filepath.Join(xdgConfigHome(), "telematik", "connectors", "active")
}

func readActiveConnector() (string, error) {
	data, err := os.ReadFile(activeConnectorFile())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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

func resolveConnectorConfigFile(name string) (string, error) {
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

	// 3. Try XDG config directory: $XDG_CONFIG_HOME/telematik/connectors/<name>.kon
	xdgDir := filepath.Join(xdgConfigHome(), "telematik", "connectors")
	xdgPath := filepath.Join(xdgDir, name+".kon")
	if _, err := os.Stat(xdgPath); err == nil {
		return xdgPath, nil
	}
	xdgPathExact := filepath.Join(xdgDir, name)
	if _, err := os.Stat(xdgPathExact); err == nil {
		return xdgPathExact, nil
	}

	return "", fmt.Errorf("configuration %q not found (searched current directory and %s)",
		name, xdgDir)
}
