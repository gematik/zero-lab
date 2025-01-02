package zaddy

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("pep", parseCaddyfilePEP)
}

type App struct {
	JWKSPath string `json:"jwks_path,omitempty"`
	logger   *slog.Logger
	pep      *pep.PEP
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
		WithJWKSetPath(a.JWKSPath).
		WithSlogger(a.logger).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create PEP: %w", err)
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

func parseCaddyfilePEP(d *caddyfile.Dispenser, existingVal any) (interface{}, error) {
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
		default:
			return nil, d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}

	return httpcaddyfile.App{
		Name:  "zero",
		Value: caddyconfig.JSON(a, nil),
	}, nil

}

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
