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

package proxy

import (
	"bytes"
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"

	yaml "go.yaml.in/yaml/v4"
)

// InjectMode selects what a protected route forwards upstream to identify/authorize the user.
type InjectMode string

// The inject modes: nothing, the identity headers, or the session's DPoP-bound token with a fresh proof.
const (
	InjectNone     InjectMode = ""
	InjectIdentity InjectMode = "identity"
	InjectDPoP     InjectMode = "dpop"
)

// Gate selects how a route resolves the session: none (passthrough), snapshot (stateless cookie, identity
// only — the default protected gate), or session (stateful kv lookup — the full session, required for dpop
// because the DPoP key never enters the cookie).
type Gate string

// The gates, as described on Gate.
const (
	GateNone     Gate = "none"
	GateSnapshot Gate = "snapshot"
	GateSession  Gate = "session"
)

// Route maps a path prefix to an upstream. Gate selects session resolution; Scope (optional) adds a
// pep.EnforcerScope check; Inject selects what is forwarded; StripPrefix removes PathPrefix before proxying.
type Route struct {
	PathPrefix  string     `yaml:"path_prefix"`
	Upstream    string     `yaml:"upstream"`
	Gate        Gate       `yaml:"gate"`
	Scope       string     `yaml:"scope"`
	Inject      InjectMode `yaml:"inject"`
	StripPrefix bool       `yaml:"strip_prefix"`

	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

// RouteSources names where the gateway routes come from; zero-pep-proxy fills it from PEP_ROUTES_PATH,
// PEP_API_UPSTREAM and PEP_WEBAPP_UPSTREAM.
type RouteSources struct {
	// RoutesPath is a YAML routes file; when set it is authoritative and the upstreams are ignored.
	RoutesPath string
	// APIUpstream makes the /api route: DPoP injected, stateful gate, prefix stripped.
	APIUpstream string
	// WebappUpstream makes the / route: identity injected, snapshot gate.
	WebappUpstream string
}

func shortcutRoutes(apiUpstream, webappUpstream string) []Route {
	var routes []Route
	if apiUpstream != "" {
		routes = append(routes, Route{PathPrefix: "/api", Upstream: apiUpstream, Inject: InjectDPoP, Gate: GateSession, StripPrefix: true})
	}
	if webappUpstream != "" {
		routes = append(routes, Route{PathPrefix: "/", Upstream: webappUpstream, Inject: InjectIdentity, Gate: GateSnapshot})
	}
	return routes
}

// RoutesFromConfig returns the gateway routes of src. Empty = forward_auth-only (no gateway).
func RoutesFromConfig(src RouteSources) ([]Route, error) {
	if src.RoutesPath != "" {
		return loadRoutes(src.RoutesPath)
	}
	return shortcutRoutes(src.APIUpstream, src.WebappUpstream), nil
}

type routesFile struct {
	Routes []Route `yaml:"routes"`
}

func loadRoutes(path string) ([]Route, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routes %q: %w", path, err)
	}
	var f routesFile
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse routes %q: %w", path, err)
	}
	return f.Routes, nil
}

// validateRoutes defaults the gate from inject, checks the enums and the dpop⇒session rule, rejects
// empty/duplicate prefixes and bad upstreams, and returns the routes sorted longest-prefix-first.
func validateRoutes(routes []Route) ([]Route, error) {
	seen := map[string]bool{}
	out := make([]Route, len(routes))
	copy(out, routes)
	for i := range out {
		rt := &out[i]
		if rt.PathPrefix == "" {
			return nil, fmt.Errorf("route %d: empty path_prefix", i)
		}
		if seen[rt.PathPrefix] {
			return nil, fmt.Errorf("duplicate route prefix %q", rt.PathPrefix)
		}
		seen[rt.PathPrefix] = true
		u, err := url.Parse(rt.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("route %q: invalid upstream %q", rt.PathPrefix, rt.Upstream)
		}
		rt.upstream = u

		switch rt.Inject {
		case InjectNone, InjectIdentity, InjectDPoP:
		default:
			return nil, fmt.Errorf("route %q: invalid inject %q", rt.PathPrefix, rt.Inject)
		}
		if rt.Gate == "" {
			switch rt.Inject {
			case InjectDPoP:
				rt.Gate = GateSession
			case InjectIdentity:
				rt.Gate = GateSnapshot
			default:
				rt.Gate = GateNone
			}
		}
		switch rt.Gate {
		case GateNone, GateSnapshot, GateSession:
		default:
			return nil, fmt.Errorf("route %q: invalid gate %q", rt.PathPrefix, rt.Gate)
		}
		// The DPoP key + token live only in the kv, so dpop injection needs the stateful gate.
		if rt.Inject == InjectDPoP && rt.Gate != GateSession {
			return nil, fmt.Errorf("route %q: inject: dpop requires gate: session (the snapshot cookie can't carry the DPoP key)", rt.PathPrefix)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].PathPrefix) > len(out[j].PathPrefix)
	})
	return out, nil
}
