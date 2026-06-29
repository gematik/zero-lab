package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

type connectorConfigInfo struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Context string `json:"context"`
	Path    string `json:"path"`
}

func newConnectorConfigsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "configs",
		Short: "List available connector configuration files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runConnectorConfigs()
		},
	}
}

func runConnectorConfigs() error {
	configs := collectConnectorConfigs()

	if outputFlag == "json" {
		return printJSON(configs)
	}

	return printTable("NAME\tURL\tCONTEXT", func(w io.Writer) {
		for _, c := range configs {
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.URL, c.Context)
		}
	})
}

func collectConnectorConfigs() []connectorConfigInfo {
	var paths []string

	if entries, err := os.ReadDir("."); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kon") {
				paths = append(paths, e.Name())
			}
		}
	}

	xdgDir := filepath.Join(xdgConfigHome(), "telematik", "connectors")
	if entries, err := os.ReadDir(xdgDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kon") {
				paths = append(paths, filepath.Join(xdgDir, e.Name()))
			}
		}
	}

	var configs []connectorConfigInfo
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
		configs = append(configs, connectorConfigInfo{
			Name:    name,
			URL:     dk.URL,
			Context: context,
			Path:    path,
		})
	}
	return configs
}
