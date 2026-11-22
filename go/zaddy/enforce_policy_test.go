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

package zaddy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

// pathRecorder is an enforcer that lets every request through and notes the path it was shown.
type pathRecorder struct{ seen *string }

func (pathRecorder) Type() pep.EnforcerType { return "path_recorder" }

func (p pathRecorder) Apply(ctx pep.Context, next pep.HandlerFunc) {
	*p.seen = ctx.Request().URL.EscapedPath()
	next(ctx)
}

func enforcePolicy(t *testing.T, seen *string) EnforcePolicyMiddleware {
	t.Helper()
	built, err := pep.NewBuilder().Resource("https://rs.example").WithJWKSet(&jose.JSONWebKeySet{}).
		WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	return EnforcePolicyMiddleware{
		Enforcer: &pep.EnforcerHolder{Enforcer: pathRecorder{seen: seen}},
		logger:   slog.New(slog.DiscardHandler),
		app:      &App{pep: built},
	}
}

// received is a request as Caddy hands it on after a rewrite: rewritten is its URL now, sent the one the client
// sent, kept under Caddy's original-request key.
func received(t *testing.T, sent, rewritten string) *http.Request {
	t.Helper()
	original := httptest.NewRequest(http.MethodGet, "https://rs.example"+sent, http.NoBody)
	r := original.Clone(context.WithValue(original.Context(), caddyhttp.OriginalRequestCtxKey, *original))
	r.URL = &url.URL{Scheme: "https", Host: "rs.example", Path: rewritten}
	r.RequestURI = rewritten
	return r
}

type nextRecorder struct{ path *string }

func (n nextRecorder) ServeHTTP(_ http.ResponseWriter, r *http.Request) error {
	*n.path = r.URL.EscapedPath()
	return nil
}

// servers.md rule 28, "Method and path": a path the client sent in a non-canonical form is refused with 400 before
// any enforcer runs, though Caddy's matchers took its repaired form.
func TestServerRule28_EnforcePolicyRefusesANonCanonicalPathAsReceived(t *testing.T) {
	for _, sent := range []string{"/api/%61dmin", "/api/..%2Fadmin", "/api/%2e%2e/admin", "/api//admin", "/api/./admin", "/api/%252Fadmin"} {
		t.Run(sent, func(t *testing.T) {
			seen, forwarded := "", ""
			err := enforcePolicy(t, &seen).ServeHTTP(httptest.NewRecorder(), received(t, sent, "/api/admin"), nextRecorder{&forwarded})
			var handlerErr caddyhttp.HandlerError
			if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("err = %v, want a 400", err)
			}
			if seen != "" || forwarded != "" {
				t.Errorf("enforcer saw %q, next got %q", seen, forwarded)
			}
		})
	}
}

// RFC 9449 Section 4.3: the enforcer judges the path the client sent, which its DPoP proof's htu names, not the one a
// rewrite made of it; the next handler still gets the rewritten request.
func TestRFC9449_4_3_TheEnforcerSeesThePathTheClientSent(t *testing.T) {
	seen, forwarded := "", ""
	if err := enforcePolicy(t, &seen).ServeHTTP(httptest.NewRecorder(), received(t, "/public/api/items", "/api/items"), nextRecorder{&forwarded}); err != nil {
		t.Fatal(err)
	}
	if seen != "/public/api/items" {
		t.Errorf("enforcer saw %q, want the path sent", seen)
	}
	if forwarded != "/api/items" {
		t.Errorf("next got %q, want the rewritten path", forwarded)
	}
}
