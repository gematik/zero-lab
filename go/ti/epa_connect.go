package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/ti/state"
	"github.com/spf13/cobra"
)

type connectResult struct {
	Provider epa.ProviderNumber `json:"provider"`
	Env      epa.Env            `json:"env"`
	BaseURL  string             `json:"base_url,omitempty"`
	OpenedAt time.Time          `json:"opened_at"`
	OK       bool               `json:"ok"`
	Resumed  bool               `json:"resumed,omitempty"`
	Error    string             `json:"error,omitempty"`
}

func newEpaConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect [<provider>]",
		Short: "Open VAU session(s); no arg = all 3 providers, <N> = one",
		Long: "Perform the VAU handshake against one or all ePA aggregators and cache\n" +
			"session metadata. With no argument, all 3 providers are opened in parallel.\n\n" +
			"The live channel exists only for the lifetime of this CLI invocation; only\n" +
			"informational metadata is cached. Use `ti epa proxy` to keep channels warm.",
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return []string{"1", "2", "3"}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			env, _, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			targets := epa.AllProviders
			if len(args) == 1 {
				p, err := parseProvider(args[0])
				if err != nil {
					return err
				}
				targets = []epa.ProviderNumber{p}
			}
			am, err := buildAuthMethod()
			if err != nil {
				return err
			}
			sf, err := am.SecurityFunctions(cmd.Context())
			if err != nil {
				return err
			}
			st, err := loadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()

			results := connectAll(cmd.Context(), env, sf, st, targets)

			if outputFlag == "json" {
				if len(results) == 1 {
					return printJSON(results[0])
				}
				return printJSON(results)
			}
			renderConnectResults(results)
			return nil
		},
	}
	addEpaEnvFlag(cmd)
	addAuthMethodFlags(cmd)
	return cmd
}

func connectAll(ctx context.Context, env epa.Env, sf *epa.SecurityFunctions, st state.Store, providers []epa.ProviderNumber) []connectResult {
	results := make([]connectResult, len(providers))
	var wg sync.WaitGroup
	for i, p := range providers {
		wg.Add(1)
		go func(i int, p epa.ProviderNumber) {
			defer wg.Done()
			results[i] = connectOne(ctx, env, sf, st, p)
		}(i, p)
	}
	wg.Wait()
	return results
}

func connectOne(ctx context.Context, env epa.Env, sf *epa.SecurityFunctions, st state.Store, p epa.ProviderNumber) connectResult {
	r := connectResult{Provider: p, Env: env}

	// obtainSession prefers resume; falls back to fresh handshake + authorize
	// on cache miss or failed probe.
	entry, resumed, err := obtainSession(ctx, env, p, sf, st)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if err := setJSON(st, vauKeysKey(env, p), entry, state.Expire(sessionEntryTTL)); err != nil {
		r.Error = fmt.Sprintf("caching session metadata: %v", err)
		return r
	}
	r.OK = true
	r.Resumed = resumed
	r.BaseURL = entry.BaseURL
	r.OpenedAt = entry.OpenedAt
	return r
}

func renderConnectResults(results []connectResult) {
	if len(results) == 1 {
		r := results[0]
		if r.OK {
			verb := "opened"
			if r.Resumed {
				verb = "resumed"
			}
			fmt.Printf("%s VAU session to provider %d (%s)\n  base url: %s\n  opened at: %s\n  cached for: %s\n",
				verb, r.Provider, r.Env, r.BaseURL, r.OpenedAt.Format(time.RFC3339), sessionEntryTTL)
		} else {
			fmt.Printf("failed to open VAU session to provider %d (%s): %s\n", r.Provider, r.Env, r.Error)
		}
		return
	}
	printTable("PROVIDER\tENV\tSTATUS\tOPENED AT\tNOTE", func(w io.Writer) {
		for _, r := range results {
			status := "ok"
			openedAt := ""
			note := ""
			if r.OK {
				openedAt = r.OpenedAt.Format(time.RFC3339)
				if r.Resumed {
					note = "resumed"
				}
			} else {
				status = "fail"
				note = r.Error
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", r.Provider, r.Env, status, openedAt, note)
		}
	})
}
