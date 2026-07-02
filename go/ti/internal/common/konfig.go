package common

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

const ConnectorConfigEnv = "TI_CONNECTOR_CONFIG"

// ConnectorConfig is the shared -c/--connector-config flag, resolved as
// flag → env → active file → default.
var ConnectorConfig = EnvFlag{
	Name: "connector-config", Shorthand: "c", Env: ConnectorConfigEnv,
	Usage: "name or path of .kon configuration file",
}

// AddConnectorConfigFlag registers the -c/--connector-config flag plus its
// shell completion on a leaf command that needs a connector.
func AddConnectorConfigFlag(cmd *cobra.Command) {
	ConnectorConfig.Register(cmd)
	cmd.RegisterFlagCompletionFunc("connector-config", CompleteConnectorConfigNames)
}

func CompleteConnectorConfigNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	configs := CollectConnectorConfigs()
	names := make([]string, 0, len(configs))
	for _, c := range configs {
		names = append(names, c.Name)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func LoadConnectorConfig() (*kon.Dotkon, error) {
	name := ConnectorConfig.Val
	source := "flag"
	if name == "" {
		name = ConnectorConfig.EnvValue()
		source = "env " + ConnectorConfigEnv
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

	path, err := ResolveConnectorConfigFile(name)
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
	return filepath.Join(XDGConfigHome(), "telematik", "connectors", "active")
}

func readActiveConnector() (string, error) {
	data, err := os.ReadFile(activeConnectorFile())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func ResolveConnectorConfigFile(name string) (string, error) {
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
	xdgDir := filepath.Join(XDGConfigHome(), "telematik", "connectors")
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

// ActiveConnectorFile is the path of the sticky connector selection written by
// `ti connector use`.
func ActiveConnectorFile() string {
	return activeConnectorFile()
}

func LoadClient(config *kon.Dotkon) (*kon.Client, error) {
	return kon.NewClient(config)
}

func LoadServices(config *kon.Dotkon) (*kon.ConnectorServices, error) {
	httpClient, baseURL, err := kon.NewHTTPClient(config)
	if err != nil {
		return nil, err
	}
	services, err := kon.LoadConnectorServices(context.Background(), httpClient, baseURL)
	if err != nil {
		return nil, err
	}
	if config.RewriteServiceEndpoints {
		services.RewriteEndpoints(baseURL)
	}
	return services, nil
}

// ConnectorConfigInfo describes a discovered .kon file.
type ConnectorConfigInfo struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Context string `json:"context"`
	Path    string `json:"path"`
}

func CollectConnectorConfigs() []ConnectorConfigInfo {
	var paths []string

	if entries, err := os.ReadDir("."); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kon") {
				paths = append(paths, e.Name())
			}
		}
	}

	xdgDir := filepath.Join(XDGConfigHome(), "telematik", "connectors")
	if entries, err := os.ReadDir(xdgDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kon") {
				paths = append(paths, filepath.Join(xdgDir, e.Name()))
			}
		}
	}

	var configs []ConnectorConfigInfo
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("could not read .kon file", "path", path, "err", err)
			continue
		}
		dk, err := kon.ParseDotkon(data)
		if err != nil {
			slog.Warn("could not parse .kon file", "path", path, "err", err)
			continue
		}
		name := strings.TrimSuffix(filepath.Base(path), ".kon")
		context := strings.Join([]string{dk.MandantId, dk.WorkplaceId, dk.ClientSystemId}, "/")
		configs = append(configs, ConnectorConfigInfo{
			Name:    name,
			URL:     dk.URL,
			Context: context,
			Path:    path,
		})
	}
	return configs
}
