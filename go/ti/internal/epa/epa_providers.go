package epa

import (
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

type providerInfo struct {
	Provider epa.ProviderNumber `json:"provider"`
	Env      epa.Env            `json:"env"`
	BaseURL  string             `json:"base_url"`
}

func newEpaProvidersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List the ePA aggregator providers for the current env",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			env, _, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			infos := make([]providerInfo, len(epa.AllProviders))
			for i, p := range epa.AllProviders {
				infos[i] = providerInfo{Provider: p, Env: env, BaseURL: epa.ResolveBaseURL(env, p)}
			}
			if common.OutputFlag == "json" {
				return common.PrintJSON(infos)
			}
			return common.PrintTable("PROVIDER\tENV\tBASE URL", func(w io.Writer) {
				for _, info := range infos {
					fmt.Fprintf(w, "%d\t%s\t%s\n", info.Provider, info.Env, info.BaseURL)
				}
			})
		},
	}
	addEpaEnvFlag(cmd)
	return cmd
}
