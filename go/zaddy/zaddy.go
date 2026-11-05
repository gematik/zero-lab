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

// Package zaddy plugs the policy enforcement point of package pep into Caddy: the app "zero", configured
// by the global option pep, and the HTTP handler enforce_policy.
package zaddy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("pep", parseCaddyfilePEP)
}

// App is the Caddy app "zero". It owns the PEP that every enforce_policy handler evaluates requests with.
type App struct {
	Resource            string `json:"resource"`
	AuthorizationServer string `json:"authorization_server"`
	JWKSPath            string `json:"jwks_path"` // if set, it will be used otherwise the JWKS from authorization_server will be used
	// PublicOrigin is the scheme, host and port clients reach this server at; DPoP proofs' htu are checked
	// against it plus the request path (RFC 9449 Section 4.3). Defaults to the origin of Resource.
	PublicOrigin string `json:"public_origin"`
	// DPoPNonceKeyringPath names the kv keyring (kv.LoadKeyring) the DPoP nonces of nonce_required are sealed
	// under. Every replica behind one origin needs the same keyring to accept the others' nonces (RFC 9449
	// Section 9); without one, a key of this process alone, enough for a single replica.
	DPoPNonceKeyringPath string `json:"dpop_nonce_keyring_path"`

	logger *slog.Logger
	pep    *pep.PEP
}

// CaddyModule registers App under the module ID "zero".
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "zero",
		New: func() caddy.Module { return new(App) },
	}
}

// Start builds the PEP from the app's configuration; Caddy does not start if that fails.
func (a *App) Start() error {
	a.logger.Info("Starting Zero app")
	nonces, err := a.dpopNonces()
	if err != nil {
		return fmt.Errorf("DPoP nonces: %w", err)
	}
	a.pep, err = pep.NewBuilder().
		Resource(a.Resource).
		PublicOrigin(a.PublicOrigin).
		WithJWKSetPath(a.JWKSPath).
		WithDPoPNonces(nonces).
		WithSlogger(a.logger).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create PEP: %w", err)
	}

	a.logger.Info("PEP successfully created", "jwks_path", a.JWKSPath)

	return nil
}

// dpopNonces are the resource server nonces of nonce_required, sealed under the configured keyring.
func (a *App) dpopNonces() (*nonce.Source, error) {
	var keys nonce.Keys
	if a.DPoPNonceKeyringPath != "" {
		ring, err := kv.LoadKeyring(a.DPoPNonceKeyringPath)
		if err != nil {
			return nil, err
		}
		keys = ring
	} else {
		a.logger.Warn("dpop_nonce_keyring_path not set: DPoP nonces hold for this replica only")
		ephemeral, err := nonce.NewEphemeralKeys()
		if err != nil {
			return nil, err
		}
		keys = ephemeral
	}
	return nonce.NewSource(keys, dpopNoncePurpose, dpopNonceTTL)
}

const (
	dpopNoncePurpose = "zaddy/dpop-nonce"
	// dpopNonceTTL is how long a nonce is accepted: long enough for a client's next requests, short enough
	// that a captured one soon stops working (RFC 9449 Section 8).
	dpopNonceTTL = 5 * time.Minute
)

// Stop closes the PEP.
func (a *App) Stop() error {
	a.logger.Info("Stopping Zero app")
	return a.pep.Close()
}

// Provision takes the app's logger from ctx.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Slogger()
	return nil
}

// Validate rejects a configuration without jwks_path.
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
		case "public_origin":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.PublicOrigin = d.Val()
		case "dpop_nonce_keyring_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.DPoPNonceKeyringPath = d.Val()
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
