package zaddy

import (
	"encoding/json"
	"errors"
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
	Scope  string `json:"scope,omitempty"`
	logger *slog.Logger
	app    *App
}

func (EnforcePolicyMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.enforce_policy",
		New: func() caddy.Module { return new(EnforcePolicyMiddleware) },
	}
}

func (m *EnforcePolicyMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Slogger()
	app, err := ctx.AppIfConfigured("zero")
	if err != nil {
		return err
	}

	zeroApp, ok := app.(*App)
	if !ok {
		return errors.New("app is not of type zaddy.App")
	}

	m.app = zeroApp

	m.logger.Info("Provisioned EnforcePolicyMiddleware", "x", ctx.Module().CaddyModule().ID)

	return nil
}

// Validate implements caddy.Validator.
func (m *EnforcePolicyMiddleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m EnforcePolicyMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := new(pep.RequestContext)
	pepErr := m.app.pep.VerifyHeaders(ctx, r)
	if pepErr != nil {
		return m.writePEPError(w, pepErr)
	}
	pepErr = m.app.pep.VerifyAccessToken(ctx, r)
	if pepErr != nil {
		return m.writePEPError(w, pepErr)
	}
	return next.ServeHTTP(w, r)
}

func (m EnforcePolicyMiddleware) writePEPError(w http.ResponseWriter, err *pep.Error) error {
	m.logger.Debug("PEP error occured", "error", err)
	w.WriteHeader(err.HttpStatus)
	return json.NewEncoder(w).Encode(err)
}

// Caddyfile parsing
// Structure:
//
//	enforce_policy {
//	   scope <scope>
//	}
func (m *EnforcePolicyMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// consume the option name
	if !d.Next() {
		return d.ArgErr()
	}

	// handle the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "scope":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Scope = d.Val()
		default:
			return d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}
	return nil
}

func parseCaddyfileEnforcePolicy(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m EnforcePolicyMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*EnforcePolicyMiddleware)(nil)
	_ caddy.Validator             = (*EnforcePolicyMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*EnforcePolicyMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*EnforcePolicyMiddleware)(nil)
)
