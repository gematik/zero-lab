package zaddy

import (
	"log/slog"
	"net/http"

	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gematik/zero-lab/go/asl"
)

func init() {
	caddy.RegisterModule(AslMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("asl_cert_data", parseCaddyfileAslHandler)
	httpcaddyfile.RegisterHandlerDirective("asl", parseCaddyfileAslHandler)
}

type AslGlobalConfig struct {
	CertPath      string   `json:"cert_path"`
	KeyPath       string   `json:"key_path"`
	CAPath        string   `json:"ca_path"`
	RCAChainPaths []string `json:"rca_chain_paths"`
	Upstream      string   `json:"upstream,omitempty"`
}

func parseAslGlobalConfig(d *caddyfile.Dispenser) (*AslGlobalConfig, error) {
	cfg := new(AslGlobalConfig)

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "cert":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.CertPath = d.Val()
		case "key":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.KeyPath = d.Val()
		case "ca":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.CAPath = d.Val()
		case "rca_chain":
			paths := make([]string, 0)
			for d.NextArg() {
				paths = append(paths, d.Val())
			}
			cfg.RCAChainPaths = paths
		case "upstream":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.Upstream = d.Val()
		default:
			return nil, d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}

	return cfg, nil
}

func (a *App) startAslServer() error {
	if a.AslConfig == nil {
		return nil
	}

	a.logger.Info("Starting ASL server", "upstream", a.AslConfig.Upstream)

	var err error
	a.aslServer, err = asl.NewServer()
	if err != nil {
		return err
	}

	return nil
}

type AslMiddlewareMode int

const (
	AslMiddlewareModeAsl AslMiddlewareMode = iota
	AslMiddlewareModeCertData
)

type AslMiddleware struct {
	Mode   AslMiddlewareMode
	logger *slog.Logger
	app    *App
}

func (AslMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.asl",
		New: func() caddy.Module { return new(AslMiddleware) },
	}
}

func (m *AslMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Slogger()
	var err error
	if m.app, err = getZeroApp(ctx); err != nil {
		return err
	}

	return nil
}

// Validate implements caddy.Validator.
func (m *AslMiddleware) Validate() error {
	return nil
}

func (m AslMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.logger.Warn("AslMiddleware", "upstream", m.app.AslConfig.Upstream)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "ASL Middleware", "mode": "` + fmt.Sprint(m.Mode) + `"}`))
	return nil
}

func parseCaddyfileAslHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m AslMiddleware

	d := h.Dispenser

	d.Next() // consume the directive

	switch d.Val() {
	case "asl_cert_data":
		m.Mode = AslMiddlewareModeCertData
	case "asl":
		m.Mode = AslMiddlewareModeAsl
	default:
		return nil, d.ArgErr()

	}

	return m, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AslMiddleware)(nil)
	_ caddy.Validator             = (*AslMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AslMiddleware)(nil)
)
