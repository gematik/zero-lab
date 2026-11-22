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
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
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
		builder = builder.WithKeySource(keys)
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

// followAuthorizationServerKeys fetches the authorization server's keys through the egress client (servers.md
// rule 30) and keeps fetching them in the background until Stop.
func (a *App) followAuthorizationServerKeys() (*authorizationServerKeys, error) {
	client := a.egressClient
	if client == nil {
		var err error
		if client, err = egress.NewClient(keysFetchTimeout, egress.Options{}); err != nil {
			return nil, fmt.Errorf("egress client: %w", err)
		}
	}
	keys, err := newAuthorizationServerKeys(context.Background(), a.AuthorizationServer, client, time.Now)
	if err != nil {
		return nil, err
	}
	var ctx context.Context
	ctx, a.stopKeys = context.WithCancel(context.Background())
	go keys.run(ctx, keysRefreshPeriod, a.logger)
	return keys, nil
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
		if err := checkIssuer(a.AuthorizationServer); err != nil {
			return fmt.Errorf("authorization_server: %w", err)
		}
	}
	if err := checkScopes(a.ScopesSupported); err != nil {
		return fmt.Errorf("scopes_supported: %w", err)
	}
	if err := checkMetadataMembers(a.MetadataMembers); err != nil {
		return fmt.Errorf("metadata_member: %w", err)
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

// maxMetadataMemberBytes bounds the JSON value of one metadata member; the document is served on every request
// for it.
const maxMetadataMemberBytes = 4096

// checkScopes takes scope tokens as RFC 6749 Section 3.3 has them, each once.
func checkScopes(scopes []string) error {
	for i, scope := range scopes {
		if scope == "" {
			return errors.New("an empty scope")
		}
		for j := range len(scope) {
			// NQCHAR: %x21 / %x23-5B / %x5D-7E
			if c := scope[j]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return errors.New("a scope with a character RFC 6749 Section 3.3 does not allow")
			}
		}
		if slices.Contains(scopes[:i], scope) {
			return errors.New("a scope named twice")
		}
	}
	return nil
}

// checkMetadataMembers takes members whose names are none of the typed members of the resource's metadata and
// whose values are each one valid JSON text within maxMetadataMemberBytes.
func checkMetadataMembers(members map[string]string) error {
	for name, value := range members {
		if name == "" {
			return errors.New("a member without a name")
		}
		if pep.IsProtectedResourceMetadataMember(name) {
			return fmt.Errorf("%s is a member zaddy sets from its configuration", name)
		}
		if len(value) > maxMetadataMemberBytes {
			return fmt.Errorf("%s: value larger than %d bytes", name, maxMetadataMemberBytes)
		}
		if !jsontext.Value(value).IsValid() {
			return fmt.Errorf("%s: value is not one JSON text; quote a string in backticks, as `\"required\"`", name)
		}
	}
	return nil
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
