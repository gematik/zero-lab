package zaddy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gematik/zero-lab/go/asl"
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("pep", parseCaddyfilePEP)
}

type App struct {
	Resource            string           `json:"resource"`
	AuthorizationServer string           `json:"authorization_server"`
	JWKSPath            string           `json:"jwks_path"` // if set, it will be used otherwise the JWKS from authorization_server will be used
	AslConfig           *AslGlobalConfig `json:"asl,omitempty"`

	logger    *slog.Logger
	pep       *pep.PEP
	aslServer *asl.Server
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "zero",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Start() error {
	a.logger.Info("Starting Zero app")
	var err error
	a.pep, err = pep.NewBuilder().
		Resource(a.Resource).
		WithJWKSetPath(a.JWKSPath).
		WithSlogger(a.logger).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create PEP: %w", err)
	}

	if err := a.startAslServer(); err != nil {
		return fmt.Errorf("starting ASL: %w", err)
	}

	a.logger.Info("PEP successfully created", "jwks_path", a.JWKSPath)

	return nil
}

func (a *App) Stop() error {
	a.logger.Info("Stopping Zero app")
	a.pep.Close()
	return nil
}

func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Slogger()
	return nil
}

func (a *App) Validate() error {
	if a.JWKSPath == "" {
		return errors.New("jwks_path must be set")
	}
	return nil
}

func parseCaddyfilePEP(d *caddyfile.Dispenser, existingVal any) (any, error) {
	a, ok := existingVal.(*App)
	if !ok {
		a = new(App)
	}

	if !d.Next() {
		return nil, d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "jwks_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.JWKSPath = d.Val()
		case "authorization_server":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.AuthorizationServer = d.Val()
		case "resource":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.Resource = d.Val()
		case "asl":
			var err error
			a.AslConfig, err = parseAslGlobalConfig(d)
			if err != nil {
				return nil, err
			}
		default:
			return nil, d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}

	return httpcaddyfile.App{
		Name:  "zero",
		Value: caddyconfig.JSON(a, nil),
	}, nil

}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	a.logger.Warn("ServeHTTP called")
	return next.ServeHTTP(w, r)
}

func getZeroApp(ctx caddy.Context) (*App, error) {
	app, err := ctx.AppIfConfigured("zero")
	if err != nil {
		return nil, err
	}

	zeroApp, ok := app.(*App)
	if !ok {
		return nil, errors.New("app is not of type zaddy.App")
	}

	return zeroApp, nil
}

// Interface guards
var (
	_ caddy.App                   = (*App)(nil)
	_ caddy.Validator             = (*App)(nil)
	_ caddy.Provisioner           = (*App)(nil)
	_ caddyhttp.MiddlewareHandler = (*App)(nil)
)
