package proxy

import (
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// InjectMode selects what a protected route forwards upstream to identify/authorize the user.
type InjectMode string

const (
	InjectNone     InjectMode = ""
	InjectIdentity InjectMode = "identity"
	InjectDPoP     InjectMode = "dpop"
)

// Gate selects how a route resolves the session: none (passthrough), snapshot (stateless cookie, identity
// only — the default protected gate), or session (stateful kv lookup — the full session, required for dpop
// because the DPoP key never enters the cookie).
type Gate string

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

// routesFromEnv builds the two common routes from env shortcuts: PEP_API_UPSTREAM (/api, dpop, stateful gate,
// strip) and PEP_WEBAPP_UPSTREAM (/, identity, snapshot gate). Empty when neither is set.
func routesFromEnv() []Route {
	var routes []Route
	if u := os.Getenv("PEP_API_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/api", Upstream: u, Inject: InjectDPoP, Gate: GateSession, StripPrefix: true})
	}
	if u := os.Getenv("PEP_WEBAPP_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/", Upstream: u, Inject: InjectIdentity, Gate: GateSnapshot})
	}
	return routes
}

// RoutesFromConfig returns the gateway routes from PEP_ROUTES_PATH (a YAML file, authoritative when set) or
// the PEP_API_UPSTREAM / PEP_WEBAPP_UPSTREAM env shortcuts. Empty = forward_auth-only (no gateway).
func RoutesFromConfig() ([]Route, error) {
	if p := os.Getenv("PEP_ROUTES_PATH"); p != "" {
		return loadRoutes(p)
	}
	return routesFromEnv(), nil
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
	if err := yaml.Unmarshal(b, &f); err != nil {
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
