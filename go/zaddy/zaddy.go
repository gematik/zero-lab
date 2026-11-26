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
// by the global option pep, and the HTTP handlers enforce_policy and protected_resource_metadata.
package zaddy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/certmagic"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/egress"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("pep", parseCaddyfilePEP)
}

// App is the Caddy app "zero". It owns the PEP that every enforce_policy handler evaluates requests with.
type App struct {
	Resource string `json:"resource"`
	// AuthorizationServer is the issuer identifier of the authorization server (RFC 8414 Section 2), named in the
	// resource's metadata. Without JWKSPath the verification keys are read from the jwks_uri of its metadata.
	AuthorizationServer string `json:"authorization_server"`
	// JWKSPath names a file with the verification keys, read once at start (servers.md rule 8); without it the keys
	// come from AuthorizationServer.
	JWKSPath string `json:"jwks_path"`
	// ScopesSupported are the scopes the resource's metadata lists (RFC 9728 Section 2).
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// MetadataMembers are members the deployment adds to the resource's metadata, by name, each value a JSON text,
	// such as gematik's zeta_asl_use. A member zaddy sets itself, or another of RFC 9728's typed members, is refused.
	MetadataMembers map[string]string `json:"metadata_members,omitempty"`
	// PublicOrigin is the scheme, host and port clients reach this server at; DPoP proofs' htu are checked
	// against it plus the request path (RFC 9449 Section 4.3). Defaults to the origin of Resource.
	PublicOrigin string `json:"public_origin"`
	// DPoPNonceKeyringPath names the key file, in the format of kv's keyring, the DPoP nonces of nonce_required
	// are sealed under. Every replica behind one origin needs the same keys to accept the others' nonces
	// (RFC 9449 Section 9); without one, a key of this process alone, enough for a single replica. It is read at
	// provisioning, so a rotated file takes effect with a config reload.
	DPoPNonceKeyringPath string `json:"dpop_nonce_keyring_path"`
	// DPoPReplays says where accepted DPoP proofs are remembered (RFC 9449 Section 11.1): "storage" in Caddy's
	// storage, which every replica configured with the same storage shares; "memory" or empty in this process,
	// which detects a proof replayed at this replica only.
	DPoPReplays string `json:"dpop_replays,omitempty"`
	// AcceptUntypedAccessTokens takes access tokens whose typ is not at+jwt (RFC 9068 Section 4), for an
	// authorization server known to omit it; without it such a token is refused.
	AcceptUntypedAccessTokens bool `json:"accept_untyped_access_tokens,omitempty"`
	// RevocationsDatabaseURL is the Postgres DSN of the kv store zero-pep-proxy keeps its session revocations
	// in. The SessionCookie enforcer admits zero-pep-proxy's session snapshots only while their session is not
	// revoked, so a policy using it is refused without this.
	RevocationsDatabaseURL string `json:"revocations_database_url,omitempty"`
	// RevocationsDatabasePlaintextAccepted is the operator's acceptance of a connection to that database
	// without TLS (servers.md rule 29); without it the connection is TLS with the server's certificate
	// verified. RevocationsDatabaseTLSCAPath names a CA bundle for it instead of the system's roots.
	RevocationsDatabasePlaintextAccepted bool   `json:"revocations_database_plaintext_accepted,omitempty"`
	RevocationsDatabaseTLSCAPath         string `json:"revocations_database_tls_ca_path,omitempty"`
	// EgressProxyCredentialsPath names the file with the forward proxy's user:password; the proxy itself comes
	// from HTTPS_PROXY, HTTP_PROXY and NO_PROXY in the environment, as for every egress client (servers.md rule 30).
	EgressProxyCredentialsPath string `json:"egress_proxy_credentials_path,omitempty"`

	logger          *slog.Logger
	nonceKeys       nonce.Keys
	storage         certmagic.Storage
	stopReplays     context.CancelFunc
	openRevocations openRevocationsFunc
	stopRevocations func()
	stopKeys        context.CancelFunc
	// egressClient reaches the authorization server; nil means egress.NewClient, and tests set one that trusts
	// their server.
	egressClient *http.Client
	pep          *pep.PEP
}

// CaddyModule registers App under the module ID "zero".
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "zero",
		New: func() caddy.Module { return new(App) },
	}
}

// Start follows the session revocations and builds the PEP from the app's configuration; Caddy does not start
// if either fails (server rule 17): a replica that cannot follow the revocations would admit signed-out sessions.
func (a *App) Start() error {
	a.logger.Info("Starting Zero app")
	nonces, err := a.dpopNonces()
	if err != nil {
		return fmt.Errorf("DPoP nonces: %w", err)
	}
	revocations, err := a.followRevocations()
	if err != nil {
		return fmt.Errorf("session revocations: %w", err)
	}
	builder := pep.NewBuilder()
	if a.AcceptUntypedAccessTokens {
		builder = builder.AcceptUntypedAccessTokens()
	}
	if a.JWKSPath != "" {
		builder = builder.WithJWKSetPath(a.JWKSPath)
	} else {
		keys, err := a.followAuthorizationServerKeys()
		if err != nil {
			a.stopBackground()
			return fmt.Errorf("keys of authorization_server: %w", err)
		}
		builder = builder.WithJWKSetFunc(keys.Keys)
	}
	a.pep, err = builder.
		Resource(a.Resource).
		PublicOrigin(a.PublicOrigin).
		WithDPoPNonces(nonces).
		WithDPoPReplays(a.dpopReplays()).
		WithSessionRevocations(revocations).
		WithSlogger(a.logger).
		Build()
	if err != nil {
		// Caddy does not stop an app that failed to start.
		a.stopBackground()
		return fmt.Errorf("failed to create PEP: %w", err)
	}

	if a.JWKSPath != "" {
		a.logger.Info("PEP successfully created", "jwks_path", a.JWKSPath)
	} else {
		a.logger.Info("PEP successfully created", "jwks_from", a.AuthorizationServer)
	}

	return nil
}

// egressProxyFileOption stands for the egress_proxy_credentials_path option where egress.ProxyFromHost asks for
// the variable that names the credentials file.
const egressProxyFileOption = "egress_proxy_credentials_path"

// followAuthorizationServerKeys fetches the authorization server's keys through the egress client (servers.md
// rule 30) and fetches them again every keysRefreshPeriod until Stop; pep starts no goroutine, so the loop is the
// app's.
func (a *App) followAuthorizationServerKeys() (*pep.AuthorizationServerKeys, error) {
	client := a.egressClient
	if client == nil {
		var err error
		proxy, err := egress.ProxyFromHost(func(name string) string {
			if name == egressProxyFileOption {
				return a.EgressProxyCredentialsPath
			}
			return os.Getenv(name)
		}, os.ReadFile, egressProxyFileOption)
		if err != nil {
			return nil, err
		}
		a.logger.Info("egress forward proxy", "proxy", proxy.String())
		if client, err = egress.NewClient(keysFetchTimeout, egress.Options{Proxy: proxy}); err != nil {
			return nil, fmt.Errorf("egress client: %w", err)
		}
	}
	keys, err := pep.NewAuthorizationServerKeys(pep.AuthorizationServerKeysConfig{
		Issuer:     a.AuthorizationServer,
		HTTPClient: client,
		Logger:     a.logger,
	})
	if err != nil {
		return nil, err
	}
	if _, err := keys.Fetch(context.Background()); err != nil {
		return nil, err
	}
	var ctx context.Context
	ctx, a.stopKeys = context.WithCancel(context.Background())
	go refreshKeys(ctx, keys, keysRefreshPeriod, a.logger)
	return keys, nil
}

const (
	// keysFetchTimeout bounds each request of the egress client (servers.md rule 24).
	keysFetchTimeout = 10 * time.Second
	// keysRefreshPeriod is how often the set is fetched in the background, outside the request path (servers.md
	// rule 8), so a key the authorization server withdraws leaves the set without a restart.
	keysRefreshPeriod = 15 * time.Minute
)

// refreshKeys fetches the set every period until ctx ends; a failed fetch keeps the set in force and is logged.
func refreshKeys(ctx context.Context, keys *pep.AuthorizationServerKeys, period time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := keys.Fetch(ctx); err != nil {
				logger.Error("Keys of the authorization server not refreshed, the set in force is kept", "error", err)
			}
		}
	}
}

// dpopReplays are the replays DPoPReplays names. Those in storage are swept of expired records until Stop.
func (a *App) dpopReplays() dpop.Replays {
	if a.DPoPReplays != dpopReplaysStorage {
		a.logger.Warn("DPoP replay detection holds for this replica only: set dpop_replays storage to share it through Caddy's storage")
		return dpop.NewMemoryReplays(dpopReplaysLimit, nil)
	}
	attrs := []any{"storage", fmt.Sprintf("%T", a.storage)}
	if fileStorage, ok := a.storage.(*certmagic.FileStorage); ok {
		// Caddy's default storage: shared only if every replica mounts the same path.
		attrs = append(attrs, "path", fileStorage.Path)
	}
	a.logger.Info("DPoP replays kept in Caddy's storage, shared by every replica on the same storage", attrs...)
	replays := newStorageReplays(a.storage, nil, a.logger)
	var ctx context.Context
	ctx, a.stopReplays = context.WithCancel(context.Background())
	go replays.run(ctx)
	return replays
}

// dpopNonces are the resource server nonces of nonce_required, sealed under the keys read at provisioning.
func (a *App) dpopNonces() (*nonce.Source, error) {
	return nonce.NewSource(a.nonceKeys, dpopNoncePurpose, dpopNonceTTL)
}

// loadNonceKeys reads the key file of the DPoP nonces; a file that does not parse refuses provisioning.
func (a *App) loadNonceKeys() error {
	if a.DPoPNonceKeyringPath == "" {
		a.logger.Warn("dpop_nonce_keyring_path not set: DPoP nonces hold for this replica only")
		keys, err := nonce.NewEphemeralKeys()
		if err != nil {
			return err
		}
		a.nonceKeys = keys
		return nil
	}
	keys, err := loadNonceKeys(a.DPoPNonceKeyringPath)
	if err != nil {
		return fmt.Errorf("dpop_nonce_keyring_path: %w", err)
	}
	a.nonceKeys = keys
	return nil
}

const (
	// dpopReplaysLimit bounds the proofs remembered at once; beyond it, proofs are refused until older ones expire.
	dpopReplaysLimit = 100_000
	// dpopReplaysStorage and dpopReplaysMemory are the values of DPoPReplays.
	dpopReplaysStorage = "storage"
	dpopReplaysMemory  = "memory"

	dpopNoncePurpose = "zaddy/dpop-nonce"
	// dpopNonceTTL is how long a nonce is accepted: long enough for a client's next requests, short enough
	// that a captured one soon stops working (RFC 9449 Section 8).
	dpopNonceTTL = 5 * time.Minute
)

// Stop ends the sweep of DPoP replays and the following of revocations, and closes the PEP.
func (a *App) Stop() error {
	a.logger.Info("Stopping Zero app")
	a.stopBackground()
	return a.pep.Close()
}

func (a *App) stopBackground() {
	if a.stopReplays != nil {
		a.stopReplays()
	}
	if a.stopRevocations != nil {
		a.stopRevocations()
	}
	if a.stopKeys != nil {
		a.stopKeys()
	}
}

// Provision takes the app's logger and storage from ctx and reads the DPoP nonce keys.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Slogger()
	if a.DPoPReplays == dpopReplaysStorage {
		if a.storage = ctx.Storage(); a.storage == nil {
			return errors.New("dpop_replays storage: Caddy has no storage configured")
		}
	}
	return a.loadNonceKeys()
}

// Validate rejects a configuration without resource, without both jwks_path and authorization_server, with an
// authorization_server that is no issuer identifier, with metadata members zaddy cannot serve, or with an unknown
// dpop_replays. Without a resource no token's audience could be checked, so any token of the authorization server
// would do (RFC 9700 Section 4.10.2).
func (a *App) Validate() error {
	if a.Resource == "" {
		return errors.New("resource must be set: the URI the access tokens' aud names")
	}
	if _, err := pep.ProtectedResourceMetadataURL(a.Resource); err != nil {
		return fmt.Errorf("resource: %w", err)
	}
	if a.JWKSPath == "" && a.AuthorizationServer == "" {
		return errors.New("jwks_path or authorization_server must be set: the keys access tokens are verified with")
	}
	if a.AuthorizationServer != "" {
		if err := pep.CheckIssuer(a.AuthorizationServer); err != nil {
			return fmt.Errorf("authorization_server: %w", err)
		}
	}
	if _, err := pep.NewProtectedResourceMetadataHandler(a.protectedResourceMetadata()); err != nil {
		return fmt.Errorf("scopes_supported or metadata_member: %w", err)
	}
	switch a.DPoPReplays {
	case "", dpopReplaysMemory, dpopReplaysStorage:
	default:
		return fmt.Errorf("dpop_replays must be %q or %q", dpopReplaysMemory, dpopReplaysStorage)
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
		case "dpop_replays":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.DPoPReplays = d.Val()
		case "revocations_database_url":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.RevocationsDatabaseURL = d.Val()
		case "revocations_database_plaintext_accepted":
			// Read as an agreement: one exact value, so that nothing else reads as consent.
			if !d.NextArg() || d.Val() != "true" {
				return nil, d.Errf("revocations_database_plaintext_accepted: true, or not set")
			}
			a.RevocationsDatabasePlaintextAccepted = true
		case "revocations_database_tls_ca_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.RevocationsDatabaseTLSCAPath = d.Val()
		case "egress_proxy_credentials_path":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			a.EgressProxyCredentialsPath = d.Val()
		case "scopes_supported":
			scopes := d.RemainingArgs()
			if len(scopes) == 0 {
				return nil, d.ArgErr()
			}
			a.ScopesSupported = append(a.ScopesSupported, scopes...)
		case "metadata_member":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return nil, d.ArgErr()
			}
			if _, named := a.MetadataMembers[args[0]]; named {
				return nil, d.Errf("metadata_member %s named twice", args[0])
			}
			if a.MetadataMembers == nil {
				a.MetadataMembers = map[string]string{}
			}
			a.MetadataMembers[args[0]] = args[1]
		case "accept_untyped_access_tokens":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			a.AcceptUntypedAccessTokens = true
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
