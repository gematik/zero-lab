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
	"log/slog"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gematik/zero-lab/go/httpguard"
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(EnforcePolicyMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("enforce_policy", parseCaddyfileEnforcePolicy)
}

// EnforcePolicyMiddleware is the Caddy HTTP handler enforce_policy: a request reaches the next handler
// only if Enforcer lets it through, and is denied otherwise. The headers of gemSpec_ZETA A_25669-01 never
// pass from the client; ZETAUserInfo and ZETAClientData make them from the verified token's claims.
type EnforcePolicyMiddleware struct {
	Enforcer *pep.EnforcerHolder `json:"enforcer"`
	// ZETAUserInfo puts zeta-user-info into the forwarded request (A_26589-01).
	ZETAUserInfo bool `json:"zeta_user_info,omitempty"`
	// ZETAClientData puts zeta-client-data into the forwarded request; off unless the endpoint asks for it
	// (A_26492-02, A_26590-02).
	ZETAClientData bool `json:"zeta_client_data,omitempty"`
	logger         *slog.Logger
	app            *App
}

// CaddyModule registers the handler under the module ID "http.handlers.enforce_policy".
func (EnforcePolicyMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.enforce_policy",
		New: func() caddy.Module { return new(EnforcePolicyMiddleware) },
	}
}

// Provision resolves the logger and the app "zero" whose PEP the handler uses; it fails if that app is
// not configured, or if the policy uses a SessionCookie enforcer, which zaddy cannot hold (refuseSessionCookie).
func (m *EnforcePolicyMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Slogger()

	var err error
	if m.app, err = getZeroApp(ctx); err != nil {
		return err
	}

	return refuseSessionCookie(m.Enforcer)
}

// Validate implements caddy.Validator.
func (m *EnforcePolicyMiddleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. Caddy's matchers compare a decoded, case-folded path, and a
// rewrite may have changed it since, so the path as the client sent it is the one judged (servers.md rule 28,
// "Method and path"): a non-canonical one is refused before any enforcer runs, so that a route matched in repaired
// form cannot be forwarded raw, and the enforcer sees it, so that a DPoP proof's htu is checked against the path
// the client signed (RFC 9449 Section 4.3). The next handler gets the request as Caddy has it.
func (m EnforcePolicyMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	asReceived := receivedRequest(r)
	if err := httpguard.CheckPath(asReceived.URL.EscapedPath()); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	for _, name := range pep.ZETAHeaderNames() {
		r.Header.Del(name)
	}
	pepCtx := m.app.pep.NewContext(w, asReceived)
	m.logger.Info("EnforcePolicyMiddleware", "enforcer", m.Enforcer)
	var nextErr error
	m.Enforcer.Apply(pepCtx, func(ctx pep.Context) {
		if !m.setZETAHeaders(ctx, r.Header) {
			return
		}
		nextErr = next.ServeHTTP(w, r)
	})
	return nextErr
}

// setZETAHeaders puts the configured headers of A_25669-01 into h; a request whose token lacks the claims
// they are made of is denied, since A_26589-01 makes the user data a condition of forwarding.
func (m EnforcePolicyMiddleware) setZETAHeaders(ctx pep.Context, h http.Header) bool {
	for _, header := range []struct {
		on    bool
		name  string
		value func(pep.Context) (string, error)
	}{
		{m.ZETAUserInfo, pep.HeaderZETAUserInfo, pep.ZETAUserInfo},
		{m.ZETAClientData, pep.HeaderZETAClientData, pep.ZETAClientData},
	} {
		if !header.on {
			continue
		}
		v, err := header.value(ctx)
		if err != nil {
			m.logger.Warn("request denied: no ZETA header", "header", header.name, "error", err)
			ctx.Deny(pep.ErrorAccessDeinied("the token lacks the claims the resource needs"))
			return false
		}
		h.Set(header.name, v)
	}
	return true
}

// receivedRequest is r with the URL the client sent, which Caddy keeps beside the request it rewrites; r itself
// when Caddy kept none, as outside a Caddy server.
func receivedRequest(r *http.Request) *http.Request {
	original, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
	if !ok || original.URL == nil {
		return r
	}
	received := r.Clone(r.Context())
	received.URL = original.URL
	received.RequestURI = original.RequestURI
	return received
}

// Caddyfile parsing
// Structure:
//
//	enforce_policy {
//	   zeta_user_info
//	   zeta_client_data
//	   verify_bearer
//	   scope <scope>
//	   any_of {
//			...
//		}
//		all_of {
//			...
//		}
//
//	}
func (m *EnforcePolicyMiddleware) unmarshalMultipleEnforcer(d *caddyfile.Dispenser, me pep.MultipleEnforcer, nesting int) error {
	// handle the block
	for d.NextBlock(nesting) {
		switch d.Val() {
		case "zeta_user_info", "zeta_client_data":
			if nesting != 0 || d.NextArg() {
				return d.Errf("%s takes no arguments and belongs to the enforce_policy block itself", d.Val())
			}
			if d.Val() == "zeta_user_info" {
				m.ZETAUserInfo = true
			} else {
				m.ZETAClientData = true
			}
		case "authorization_bearer":
			e := &pep.EnforcerAuthorizationBearer{
				TypeVal: pep.EnforcerTypeAuthorizationBearer,
			}
			me.Append(e)
		case "authorization_dpop":
			e := &pep.EnforcerAuthorizationDPoP{
				TypeVal: pep.EnforcerTypeAuthorizationDPoP,
			}
			for d.NextArg() {
				switch d.Val() {
				case "nonce_required":
					e.NonceRequired = true
				default:
					return d.Errf("unrecognized subdirective: %s", d.Val())
				}
			}
			me.Append(e)
		case "scope":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e := &pep.EnforcerScope{
				TypeVal: pep.EnforcerTypeScope,
				Scope:   d.Val(),
			}
			me.Append(e)
		case "any_of":
			anyOf := &pep.EnforcerAnyOf{
				TypeVal:         pep.EnforcerTypeAnyOf,
				EnforcerHolders: make([]pep.EnforcerHolder, 0),
			}
			err := m.unmarshalMultipleEnforcer(d, anyOf, nesting+1)
			if err != nil {
				return err
			}
			me.Append(anyOf)
		case "all_of":
			allOf := &pep.EnforcerAllOf{
				TypeVal:         pep.EnforcerTypeAllOf,
				EnforcerHolders: make([]pep.EnforcerHolder, 0),
			}
			err := m.unmarshalMultipleEnforcer(d, allOf, nesting+1)
			if err != nil {
				return err
			}
			me.Append(allOf)
		default:
			return d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		return d.Errf("unexpected block")
	}
	return nil
}

func parseCaddyfileEnforcePolicy(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m EnforcePolicyMiddleware
	me := &pep.EnforcerAllOf{
		TypeVal:         pep.EnforcerTypeAllOf,
		EnforcerHolders: make([]pep.EnforcerHolder, 0),
	}
	// consume the option name
	if !h.Next() {
		return nil, h.ArgErr()
	}
	err := m.unmarshalMultipleEnforcer(h.Dispenser, me, 0)
	if err != nil {
		return nil, err
	}
	m.Enforcer = &pep.EnforcerHolder{
		Enforcer: me,
	}
	return m, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*EnforcePolicyMiddleware)(nil)
	_ caddy.Validator             = (*EnforcePolicyMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*EnforcePolicyMiddleware)(nil)
)
