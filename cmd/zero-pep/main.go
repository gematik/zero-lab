package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/pkg/pep"
	"github.com/gematik/zero-lab/pkg/prettylog"
	"github.com/gematik/zero-lab/pkg/util"
)

func main() {
	if os.Getenv("PRETTY_LOGS") != "false" {
		logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
		slog.SetDefault(logger)
	}

	configPath := util.GetEnv("PEP_CONFIG_PATH", "config/pep.yaml")
	slog.Info("Loading PEP config", "config_path", configPath)
	p, err := pep.NewFromConfigFile(util.GetEnv("PEP_CONFIG_PATH", "config/pep.yaml"))
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("Starting PEP server", "address", p.Config.Address)

	log.Fatal(p.ListenAndServe(context.Background()))

}
