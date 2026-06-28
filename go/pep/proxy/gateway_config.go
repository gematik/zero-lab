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

// Route maps a path prefix to an upstream. Protected routes require an authenticated session; Inject (only
// meaningful when Protected) selects what is forwarded to identify/authorize the user. StripPrefix removes
// PathPrefix before proxying (so /api/x → upstream /x).
type Route struct {
	PathPrefix  string     `yaml:"path_prefix"`
	Upstream    string     `yaml:"upstream"`
	Protected   bool       `yaml:"protected"`
	Inject      InjectMode `yaml:"inject"`
	StripPrefix bool       `yaml:"strip_prefix"`

	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

// routesFromEnv builds the two common routes from env shortcuts: PEP_API_UPSTREAM (/api, DPoP, strip) and
// PEP_WEBAPP_UPSTREAM (/, identity). Empty when neither is set.
func routesFromEnv() []Route {
	var routes []Route
	if u := os.Getenv("PEP_API_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/api", Upstream: u, Protected: true, Inject: InjectDPoP, StripPrefix: true})
	}
	if u := os.Getenv("PEP_WEBAPP_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/", Upstream: u, Protected: true, Inject: InjectIdentity})
	}
	return routes
}

type routesFile struct {
	Routes []Route `yaml:"routes"`
}

// loadRoutes reads a routes YAML. Routes default to Protected=true; a route turns this off only by setting
// protected:false explicitly (yaml zero-values bool to false, so we probe which keys were present).
func loadRoutes(path string) ([]Route, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routes %q: %w", path, err)
	}
	var probe struct {
		Routes []map[string]any `yaml:"routes"`
	}
	if err := yaml.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("parse routes %q: %w", path, err)
	}
	var f routesFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse routes %q: %w", path, err)
	}
	for i := range f.Routes {
		if i < len(probe.Routes) {
			if _, set := probe.Routes[i]["protected"]; !set {
				f.Routes[i].Protected = true
			}
		}
	}
	return f.Routes, nil
}

// validateRoutes parses each upstream, rejects empty/duplicate prefixes and bad inject modes, and returns the
// routes sorted longest-prefix-first (so "/api" wins over "/").
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
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].PathPrefix) > len(out[j].PathPrefix)
	})
	return out, nil
}
