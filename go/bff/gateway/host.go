package gateway

import (
	"io/fs"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/bff"
)

// RoutesFromEnv builds the standard routes from the environment: API_UPSTREAM (/api/, DPoP-bound token)
// and WEBAPP_UPSTREAM (/, identity header). It is empty when neither is set — i.e. the classic BFF with no
// gateway. A host enables gateway mode simply by setting these.
func RoutesFromEnv() []Route {
	var routes []Route
	if u := os.Getenv("API_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/api/", UpstreamURL: u, Protected: true, Inject: InjectDPoP, StripPrefix: true})
	}
	if u := os.Getenv("WEBAPP_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/", UpstreamURL: u, Protected: true, Inject: InjectIdentity})
	}
	return routes
}

// Handler assembles the public handler for a BFF host from the same building blocks in either mode:
//   - gateway mode (cfg.Routes non-empty): auth at /bff/auth/*, the login UI at /bff/, and the gated
//     reverse proxies for everything else.
//   - classic mode (no routes): auth at /bff/*, the login UI at /.
//
// uiFS is the login UI (webui.FS). In gateway mode the host should also set the BFF's FrontendRedirectURI
// to <public>/bff/ so the OAuth callback lands on the relocated UI.
func Handler(b *bff.BackendForFrontend, uiFS fs.FS, cfg Config) (http.Handler, error) {
	mux := http.NewServeMux()
	if len(cfg.Routes) == 0 {
		b.Mount(mux)
		mux.Handle("/", http.FileServerFS(uiFS))
		return mux, nil
	}
	gw, err := New(b, cfg)
	if err != nil {
		return nil, err
	}
	mux.Handle("/bff/auth/", b.AuthHandler())
	mux.Handle("/bff/", http.StripPrefix("/bff", http.FileServerFS(uiFS)))
	mux.Handle("/", gw)
	return mux, nil
}
