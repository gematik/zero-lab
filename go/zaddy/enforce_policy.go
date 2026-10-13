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
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(EnforcePolicyMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("enforce_policy", parseCaddyfileEnforcePolicy)
}

type EnforcePolicyMiddleware struct {
	Enforcer *pep.EnforcerHolder `json:"enforcer"`
	logger   *slog.Logger
	app      *App
}

func (EnforcePolicyMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.enforce_policy",
		New: func() caddy.Module { return new(EnforcePolicyMiddleware) },
	}
}

func (m *EnforcePolicyMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Slogger()

	var err error
	if m.app, err = getZeroApp(ctx); err != nil {
		return err
	}

	return nil
}

// Validate implements caddy.Validator.
func (m *EnforcePolicyMiddleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m EnforcePolicyMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	pepCtx := m.app.pep.NewContext(w, r)
	m.logger.Info("EnforcePolicyMiddleware", "enforcer", m.Enforcer)
	m.Enforcer.Apply(pepCtx, func(ctx pep.Context) {
		next.ServeHTTP(w, r)
	})
	return nil
}

// Caddyfile parsing
// Structure:
//
//	enforce_policy {
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
func (m EnforcePolicyMiddleware) unmarshalMultipleEnforcer(d *caddyfile.Dispenser, me pep.MultipleEnforcer, nesting int) error {
	// handle the block
	for d.NextBlock(nesting) {
		switch d.Val() {
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
	if !h.Dispenser.Next() {
		return nil, h.Dispenser.ArgErr()
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
