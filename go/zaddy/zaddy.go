package zaddy

import (
	"errors"
	"log/slog"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("zero", parseCaddyfileZero)
}

type App struct {
	OAuth2ServerURI string `json:"oauth2_server_uri,omitempty"`
	logger          *slog.Logger
	pep             *pep.PEP
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "zero",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Start() error {
	a.logger.Info("Starting Zero app")
	a.pep = pep.New()
	a.pep.Logger = a.logger
	a.pep.OAuth2ServerURI = a.OAuth2ServerURI
	go a.pep.Start(caddy.Context{})
	return nil
}

func (a *App) Stop() error {
	a.logger.Info("Stopping Zero app")
	a.pep.Stop()
	return nil
}

func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Slogger()
	a.logger.Info(">>>>> Provisioning Zero app", "oauth2_server_uri", a.OAuth2ServerURI)
	return nil
}

func (a *App) Validate() error {
	if a.OAuth2ServerURI == "" {
		return errors.New("oauth2_server_uri must be set")
	}
	return nil
}

func parseCaddyfileZero(d *caddyfile.Dispenser, existingVal any) (interface{}, error) {
	a, ok := existingVal.(*App)
	if !ok {
		a = new(App)
	}

	if !d.Next() {
		return nil, d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "oauth2_server_uri":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.OAuth2ServerURI = d.Val()
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
