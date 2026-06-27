package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gematik/zero-lab/go/dpop"
)

// mountAPI mounts the gated /api reverse-proxy on the server mux when an upstream is configured (apiBackend).
func (b *pdpBackend) mountAPI(s *Server, mux *http.ServeMux) {
	if b.cfg.APIUpstream == "" {
		return
	}
	prefix := strings.TrimRight(b.cfg.APIPrefix, "/")
	mux.Handle(prefix+"/", b.apiProxy(s.currentSession))
}

// apiProxy returns a gated reverse-proxy for the binding's upstream: it requires a valid session, mints a
// fresh access token + a DPoP proof (session key) per request, replaces any client Authorization, and
// forwards. The configured upstream is the only allowed destination (BCP "validate destination" allowlist).
func (b *pdpBackend) apiProxy(currentSession func(*http.Request) (*Session, bool)) http.Handler {
	target, _ := url.Parse(b.cfg.APIUpstream)
	prefix := strings.TrimRight(b.cfg.APIPrefix, "/")
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, prefix)
			pr.Out.Host = target.Host
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := currentSession(r)
		if !ok || !sess.Authenticated() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token, err := b.FreshAccessToken(r.Context(), sess)
		if err != nil || token == "" {
			http.Error(w, "no upstream token", http.StatusBadGateway)
			return
		}
		key, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
		if err != nil {
			http.Error(w, "session key", http.StatusInternalServerError)
			return
		}
		// Bind the proof to the ACTUAL outbound request: the upstream host + the prefix-stripped path.
		out := &http.Request{Method: r.Method, URL: &url.URL{
			Scheme: target.Scheme,
			Host:   target.Host,
			Path:   strings.TrimPrefix(r.URL.Path, prefix),
		}}
		proof, err := b.signer.dpopProof(out, token, key)
		if err != nil {
			http.Error(w, "dpop proof", http.StatusInternalServerError)
			return
		}
		r.Header.Set("Authorization", "DPoP "+token) // replaces any client-supplied Authorization
		r.Header.Set(dpop.DPoPHeaderName, proof)
		rp.ServeHTTP(w, r)
	})
}
