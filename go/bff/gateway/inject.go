package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/dpop"
)

type injectionCtxKey struct{}

type injection struct {
	mode    InjectMode
	token   string
	session *bff.Session
}

func withInjection(ctx context.Context, inj *injection) context.Context {
	return context.WithValue(ctx, injectionCtxKey{}, inj)
}

func injectionFrom(ctx context.Context) *injection {
	inj, _ := ctx.Value(injectionCtxKey{}).(*injection)
	return inj
}

// newProxy builds the reverse proxy for one route. The Rewrite hook runs on the cloned outbound request:
// it retargets the upstream, refreshes X-Forwarded-*, strips any client-supplied auth/identity headers,
// then injects our own identity header or DPoP-bound token.
func (g *Gateway) newProxy(rt *Route) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(rt.upstream)
			if rt.StripPrefix {
				trimmed := strings.TrimPrefix(pr.Out.URL.Path, strings.TrimSuffix(rt.PathPrefix, "/"))
				if trimmed == "" {
					trimmed = "/"
				}
				pr.Out.URL.Path = trimmed
				pr.Out.URL.RawPath = ""
			}
			pr.SetXForwarded()

			// Never let a client forge identity or authorization to the upstream.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(g.cfg.IdentityHeader)

			inj := injectionFrom(pr.In.Context())
			if inj == nil {
				return
			}
			switch inj.mode {
			case InjectIdentity:
				if h := encodeIdentity(inj.session); h != "" {
					pr.Out.Header.Set(g.cfg.IdentityHeader, h)
				}
			case InjectDPoP:
				pr.Out.Header.Set("Authorization", "DPoP "+inj.token)
				if proof, err := g.mintDPoP(pr.Out, inj.token); err != nil {
					slog.Error("mint DPoP proof", "error", err)
				} else {
					pr.Out.Header.Set(dpop.DPoPHeaderName, proof)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("gateway upstream unreachable", "upstream", rt.upstream.String(), "error", err)
			respondJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "bad_gateway",
				"error_description": "upstream unavailable",
			})
		},
	}
}

// mintDPoP signs a resource-server DPoP proof for the outbound request: htm/htu = the upstream method+URL,
// ath = the access-token hash. Signed with the BFF's DPoP key (the token's cnf.jkt).
func (g *Gateway) mintDPoP(out *http.Request, accessToken string) (string, error) {
	proof, err := dpop.NewBuilder().HttpRequest(out).AccessTokenHashFrom(accessToken).Build()
	if err != nil {
		return "", err
	}
	return proof.Sign(g.dpopPK)
}

// encodeIdentity renders the session's identity claims as base64url(JSON) for the identity header. Returns
// "" when there is nothing to forward.
func encodeIdentity(s *bff.Session) string {
	claims := identityClaims(s)
	if len(claims) == 0 {
		return ""
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// identityClaims returns the upstream identity claims — the introspection "identity" sub-object (the user's
// id_token claims) — falling back to the whole introspection map.
func identityClaims(s *bff.Session) map[string]any {
	if s == nil || s.Identity == nil {
		return nil
	}
	if id, ok := s.Identity["identity"].(map[string]any); ok {
		return id
	}
	return s.Identity
}
