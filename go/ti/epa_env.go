package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/spf13/cobra"
)

const (
	epaEnvFlag    = "epa-env"
	epaEnvEnv     = "TI_EPA_ENV"
	epaEnvDefault = epa.EnvRef
)

var epaEnv = envFlag{
	name: epaEnvFlag, env: epaEnvEnv,
	usage: "ePA environment: dev, test, ref, prod",
}

func addEpaEnvFlag(cmd *cobra.Command) {
	epaEnv.register(cmd)
	cmd.RegisterFlagCompletionFunc(epaEnvFlag, completeEpaEnv)
}

func completeEpaEnv(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"dev", "test", "ref", "prod"}, cobra.ShellCompDirectiveNoFileComp
}

// epaEnvSource describes where the resolved env came from.
type epaEnvSource string

const (
	epaEnvFromFlag    epaEnvSource = "flag"
	epaEnvFromEnvVar  epaEnvSource = "env"
	epaEnvFromSticky  epaEnvSource = "sticky"
	epaEnvFromDefault epaEnvSource = "default"
)

// resolveEpaEnv applies the resolution chain: flag → env var → sticky → default.
func resolveEpaEnv() (epa.Env, epaEnvSource, error) {
	if epaEnv.val != "" {
		e, err := epa.EnvFromString(epaEnv.val)
		if err != nil {
			return "", "", fmt.Errorf("--%s: %w", epaEnvFlag, err)
		}
		return e, epaEnvFromFlag, nil
	}
	if v := epaEnv.envValue(); v != "" {
		e, err := epa.EnvFromString(v)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", epaEnvEnv, err)
		}
		return e, epaEnvFromEnvVar, nil
	}
	if active, err := readActiveEpaEnv(); err == nil && active != "" {
		e, err := epa.EnvFromString(active)
		if err != nil {
			return "", "", fmt.Errorf("%s points at %q which is not a valid environment; run `ti epa use <env>`", epaEnvFile(), active)
		}
		return e, epaEnvFromSticky, nil
	}
	return epaEnvDefault, epaEnvFromDefault, nil
}

func epaEnvFile() string {
	return filepath.Join(telematikDir(), "cli-epa-env")
}

func readActiveEpaEnv() (string, error) {
	data, err := os.ReadFile(epaEnvFile())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeActiveEpaEnv(env epa.Env) error {
	path := epaEnvFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	return os.WriteFile(path, []byte(env.String()+"\n"), 0o644)
}

func newEpaUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <dev|test|ref|prod>",
		Short: "Set the active ePA environment",
		Long: "Set the active ePA environment. Subsequent commands without --" + epaEnvFlag + "\n" +
			"or " + epaEnvEnv + " env var will use this selection.\n\n" +
			"The selection is stored at $XDG_CONFIG_HOME/telematik/cli-epa-env.",
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeEpaEnv(cmd, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			e, err := epa.EnvFromString(args[0])
			if err != nil {
				return err
			}
			if err := writeActiveEpaEnv(e); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "active ePA environment set to %q\n", e)
			return nil
		},
	}
}

func newEpaEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Show the current ePA environment and its source",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			e, src, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			if outputFlag == "json" {
				return printJSON(map[string]string{"env": e.String(), "source": string(src)})
			}
			fmt.Printf("%s (%s)\n", e, src)
			return nil
		},
	}
	addEpaEnvFlag(cmd)
	return cmd
}
