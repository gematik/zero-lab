// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/portal"
	"github.com/gematik/zero-lab/go/epa/ti"
)

var listenAddr = ""

func init() {
	routerCmd.Flags().StringVarP(&listenAddr, "addr", "a", ":8082", "Address to listen on")

	rootCmd.AddCommand(routerCmd)
}

var routerCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run ePA Client as Proxy",
	Run: func(_ *cobra.Command, _ []string) {
		runner, err := tiBinary()
		cobra.CheckErr(err)

		proxies := make([]*epa.Proxy, len(config.ProxyConfigs))
		proxyInfos := make([]*epa.ProxyInfo, 0, len(config.ProxyConfigs))
		for num, proxyConfig := range config.ProxyConfigs {
			proxy, err := createProxy(&proxyConfig, runner)
			cobra.CheckErr(err)
			info, err := proxy.GetProxyInfo()
			cobra.CheckErr(err)
			proxyInfos = append(proxyInfos, info)
			proxies[num] = proxy
		}

		router, err := buildRouter(proxies, proxyInfos, ti.NewProber(runner, time.Now))
		cobra.CheckErr(err)

		slog.Info("starting Proxy at " + listenAddr)
		server := &http.Server{Addr: listenAddr, Handler: router, ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(server.ListenAndServe())
	},
}

// buildRouter mounts the proxies under /api and the developer portal as
// catch-all. proxies and proxyInfos are parallel slices; the first proxy is
// additionally reachable without the /api/proxies/{name} prefix.
func buildRouter(proxies []*epa.Proxy, proxyInfos []*epa.ProxyInfo, prober *ti.Prober) (http.Handler, error) {
	if len(proxies) != len(proxyInfos) {
		return nil, fmt.Errorf("got %d proxies but %d proxy infos", len(proxies), len(proxyInfos))
	}

	mux := http.NewServeMux()

	for num, proxy := range proxies {
		if num == 0 {
			mux.Handle("/api/", http.StripPrefix("/api", proxy))
		}

		proxyRouteName := "/api/proxies/" + proxyInfos[num].Name //nolint:gosec // buildRouter returned above unless both slices have the same length, and num ranges over proxies
		mux.Handle(proxyRouteName+"/", http.StripPrefix(proxyRouteName, proxy))

		slog.Info("Registered proxy", "name", proxyInfos[num].Name, "route", proxyRouteName) //nolint:gosec // buildRouter returned above unless both slices have the same length, and num ranges over proxies
	}

	mux.HandleFunc("GET /api/proxies", func(w http.ResponseWriter, _ *http.Request) {
		var infos []*epa.ProxyInfo
		for _, proxy := range proxies {
			info, err := proxy.GetProxyInfo()
			if err != nil {
				slog.Error("Failed to get proxy info", "error", err)
				continue
			}
			infos = append(infos, info)
		}
		writeJSON(w, infos)
	})

	mux.Handle("GET /api/probe", probeHandler(prober, proxyInfos))

	webPortal, err := portal.New(proxyInfos)
	if err != nil {
		return nil, err
	}
	mux.Handle("/", webPortal)

	return mux, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("Failed to encode response", "error", err)
	}
}

// probeEntry is one environment in the answer of GET /api/probe: its report, or why there
// is none.
type probeEntry struct {
	*ti.ProbeReport
	Environment string `json:"environment"`
	Error       string `json:"error,omitempty"`
}

// probeHandler answers with the probe of each environment the proxies use, in their order.
// Like the proxies' status, a failed run appears in its entry rather than as an HTTP error,
// so that one environment's trouble leaves the others readable.
func probeHandler(prober *ti.Prober, proxyInfos []*epa.ProxyInfo) http.HandlerFunc {
	var envs []string
	for _, info := range proxyInfos {
		if env := string(info.Env); !slices.Contains(envs, env) {
			envs = append(envs, env)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		entries := make([]probeEntry, len(envs))
		var wg sync.WaitGroup
		for i, env := range envs {
			wg.Go(func() {
				entries[i].Environment = env
				report, err := prober.Probe(r.Context(), env)
				if err != nil {
					slog.Error("Failed to probe the TI services", "env", env, "error", err)
					entries[i].Error = err.Error()
					return
				}
				entries[i].ProbeReport = report
			})
		}
		wg.Wait()
		writeJSON(w, entries)
	}
}

// tiBinary is the ti tool of EPA_TI_BIN, else `ti` on the PATH.
func tiBinary() (*ti.Binary, error) {
	return ti.NewBinary(os.Getenv("EPA_TI_BIN"))
}

func createProxy(proxyConfig *epa.ProxyConfig, runner *ti.Binary) (*epa.Proxy, error) {
	proxyConfig.TI = runner
	err := proxyConfig.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security functions: %w", err)
	}
	return epa.NewProxy(proxyConfig)
}
