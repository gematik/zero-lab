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

type konConfigInfo struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Context string `json:"context"`
	Path    string `json:"path"`
}

func newKonConfigsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "configs",
		Short: "List available Konnektor configuration files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runKonConfigs()
		},
	}
}

func runKonConfigs() error {
	configs := collectKonConfigs()

	if outputFlag == "json" {
		return printJSON(configs)
	}

	return printTable("NAME\tURL\tCONTEXT", func(w io.Writer) {
		for _, c := range configs {
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.URL, c.Context)
		}
	})
}

func collectKonConfigs() []konConfigInfo {
	var paths []string

	// Current working directory
	if entries, err := os.ReadDir("."); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kon") {
				paths = append(paths, e.Name())
			}
		}
	}

	// XDG config directory
	xdgDir := filepath.Join(xdgConfigHome(), "telematik", "kon")
	if entries, err := os.ReadDir(xdgDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kon") {
				paths = append(paths, filepath.Join(xdgDir, e.Name()))
			}
		}
	}

	var configs []konConfigInfo
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
		configs = append(configs, konConfigInfo{
			Name:    name,
			URL:     dk.URL,
			Context: context,
			Path:    path,
		})
	}
	return configs
}
