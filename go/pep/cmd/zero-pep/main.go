package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/libzero/prettylog"
	"github.com/gematik/zero-lab/go/libzero/util"
	"github.com/gematik/zero-lab/go/pep"
	"github.com/spf13/viper"
)

func main() {
	viper.AddConfigPath("config")
	viper.SetConfigName("pep")
	viper.SetConfigType("yml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}
	type Config struct {
		Address string `mapstructure:"address"`
	}

	var c pep.Config
	if err := viper.Unmarshal(&c); err != nil {
		log.Fatal(err)
	}

	slog.Info("Starting PEP server", "a", viper.Get("address"))

	slog.Info("Starting PEP server", "cfg", c)
	os.Exit(1)

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
