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

// providerMappingEntry is the JSON shape stored at kvnrProviderKey(...).
type providerMappingEntry struct {
	Provider     epa.ProviderNumber `json:"provider"`
	DiscoveredAt time.Time          `json:"discovered_at"`
}

// kvnrProviderTTL controls how long we trust a cached KVNR→provider mapping
// before re-discovering. Insurants very rarely change provider; 1h is a tight
// upper bound for a CLI session.
const kvnrProviderTTL = time.Hour

type providerProbeStatus struct {
	Provider epa.ProviderNumber `json:"provider"`
	Found    bool               `json:"found"`
	Error    string             `json:"error,omitempty"`
}

type recordResult struct {
	KVNR      string                                 `json:"kvnr"`
	Env       epa.Env                                `json:"env"`
	Provider  *epa.ProviderNumber                    `json:"provider,omitempty"`
	CacheHit  bool                                   `json:"cache_hit"`
	Probes    []providerProbeStatus                  `json:"probes,omitempty"`
	Consent   *epa.GetConsentDecisionInformationType `json:"consent,omitempty"`
	InfoError string                                 `json:"info_error,omitempty"`
}

func newEpaRecordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record <kvnr>",
		Short: "Locate an insurant's record and show consent decisions",
		Long: "Locate an insurant's record across the ePA aggregators and show consent\n" +
			"decisions. The KVNR→provider mapping is cached (1h TTL) — subsequent calls\n" +
			"reuse it without fanning out.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			kvnr := args[0]
			env, _, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			st, err := loadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()
			result, err := lookupRecord(cmd.Context(), st, env, kvnr)
			if err != nil {
				return err
			}
			if outputFlag == "json" {
				return printJSON(result)
			}
			renderRecord(result)
			return nil
		},
	}
	addEpaEnvFlag(cmd)
	return cmd
}

// lookupRecord performs lazy discovery of the provider holding kvnr's record,
// then fetches consent decisions from that provider. Caches the provider
// mapping on first discovery.
func lookupRecord(ctx context.Context, st state.Store, env epa.Env, kvnr string) (*recordResult, error) {
	res := &recordResult{KVNR: kvnr, Env: env}

	// Cache hit?
	cached, hit, err := getJSON[providerMappingEntry](st, kvnrProviderKey(env, kvnr))
	if err != nil {
		return nil, err
	}
	if hit {
		p := cached.Provider
		res.Provider = &p
		res.CacheHit = true
	} else {
		// Fan out unauth GetRecordStatus across all providers.
		probes := fanOutRecordStatus(ctx, env, kvnr)
		res.Probes = probes
		for _, pr := range probes {
			if pr.Found {
				p := pr.Provider
				res.Provider = &p
				entry := providerMappingEntry{Provider: p, DiscoveredAt: time.Now().UTC()}
				if err := setJSON(st, kvnrProviderKey(env, kvnr), entry, state.Expire(kvnrProviderTTL)); err != nil {
					return nil, fmt.Errorf("caching provider mapping: %w", err)
				}
				break
			}
		}
	}

	if res.Provider == nil {
		return res, nil
	}

	// Fetch consent decisions from the resolved provider. Treat errors as
	// non-fatal — surface them on the result, still return what we have.
	client, err := newEpaClient(ctx, env, *res.Provider, nil)
	if err != nil {
		res.InfoError = err.Error()
		return res, nil
	}
	defer client.Close()
	consent, err := client.GetConsentDecisionInformation(kvnr)
	if err != nil {
		res.InfoError = err.Error()
		return res, nil
	}
	res.Consent = consent
	return res, nil
}

func fanOutRecordStatus(ctx context.Context, env epa.Env, kvnr string) []providerProbeStatus {
	probes := make([]providerProbeStatus, len(epa.AllProviders))
	var wg sync.WaitGroup
	for i, p := range epa.AllProviders {
		wg.Add(1)
		go func(i int, p epa.ProviderNumber) {
			defer wg.Done()
			probes[i] = checkRecordStatus(ctx, env, p, kvnr)
		}(i, p)
	}
	wg.Wait()
	return probes
}

func checkRecordStatus(ctx context.Context, env epa.Env, p epa.ProviderNumber, kvnr string) providerProbeStatus {
	out := providerProbeStatus{Provider: p}
	client, err := newEpaClient(ctx, env, p, nil) // /information endpoint doesn't use SecurityFunctions
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer client.Close()
	found, err := client.GetRecordStatus(kvnr)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Found = found
	return out
}

func renderRecord(r *recordResult) {
	if r.Provider == nil {
		fmt.Printf("no record for %s in %s\n", r.KVNR, r.Env)
		if len(r.Probes) > 0 {
			printTable("PROVIDER\tFOUND\tNOTE", func(w io.Writer) {
				for _, p := range r.Probes {
					note := p.Error
					if note == "" {
						note = "ok"
					}
					fmt.Fprintf(w, "%d\t%v\t%s\n", p.Provider, p.Found, note)
				}
			})
		}
		return
	}

	cacheNote := ""
	if r.CacheHit {
		cacheNote = " (cached)"
	}
	fmt.Printf("record for %s in %s is on provider %d%s\n", r.KVNR, r.Env, *r.Provider, cacheNote)

	if r.InfoError != "" {
		fmt.Printf("consent lookup failed: %s\n", r.InfoError)
		return
	}
	if r.Consent == nil || len(r.Consent.Data) == 0 {
		fmt.Println("consent decisions: (none)")
		return
	}
	fmt.Println()
	fmt.Println("consent decisions:")
	printTable("FUNCTION\tDECISION", func(w io.Writer) {
		for _, d := range r.Consent.Data {
			fmt.Fprintf(w, "%s\t%s\n", d.FunctionId, d.Decision)
		}
	})
}
