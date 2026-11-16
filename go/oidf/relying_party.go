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

package oidf

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/gematik/zero-lab/go/openid"
)

// defaultOPScopes are requested from an OpenID provider when RelyingPartyConfig.Scopes is unset — the
// minimal identity set (display name + insured/KVNR).
var defaultOPScopes = []string{"openid", "urn:telematik:display_name", "urn:telematik:versicherter"}

// RelyingPartyConfig configures a gematik OpenID Federation relying party. It holds no key: [New] takes the keys as
// [Keys], and a configuration file names their files in [KeyFiles] beside it. Only deployment-specific values
// are required; the invariant gematik OIDF metadata (response_types, grant_types, client_registration_types,
// token_endpoint_auth_method, id_token algorithms, PAR) is filled in by buildMetadata.
type RelyingPartyConfig struct {
	// Subject is this relying party's entity identifier — its own public URL — and also the entity
	// statement's iss/sub and the OIDF client_id.
	Subject string `json:"entity" yaml:"entity"`

	// FedMasterURL is the federation master's entity identifier. Its trust-anchor signing key is resolved from a
	// built-in table of known gematik masters (see knownFedMasters); set FedMasterJWK to override or for an unlisted
	// master. Exactly one of FedMasterURL and FedMasterEntityStatementURI is set.
	FedMasterURL string `json:"master,omitzero" yaml:"master,omitempty"`
	// FedMasterEntityStatementURI names the master by the location of its entity configuration: an https URI without
	// query, fragment or user info, ending in exactly "/.well-known/openid-federation". The entity identifier is what
	// precedes that suffix. The URI is a location, not a source of trust: an unlisted master's key comes from
	// FedMasterJWK, obtained out of band.
	FedMasterEntityStatementURI string `json:"master_entity_statement_uri,omitzero" yaml:"master_entity_statement_uri,omitempty"`
	FedMasterJWK                *Jwk   `json:"master_jwk,omitzero" yaml:"master_jwk,omitempty"`

	// RelyingParty + FederationEntity are the deployment-specific entity-statement metadata; the rest is
	// defaulted.
	RelyingParty     RelyingPartyMetadata `json:"relying_party" yaml:"relying_party"`
	FederationEntity FederationEntity     `json:"federation_entity" yaml:"federation_entity"`

	// Scopes requested from the OpenID provider's authorization endpoint (which identity claims it returns).
	// When empty, defaultOPScopes is used.
	Scopes []string `json:"scopes,omitzero" yaml:"scopes,omitempty"`

	// APIKey is the key of gematik's development federation (*.dev.gematik.solutions). Not serialized; the
	// program supplies it, the library reads no environment.
	APIKey string `json:"-" yaml:"-"`

	// HTTPClient is the base client for federation and relying-party calls. Not serialized; supplied
	// programmatically. When nil, a client with a default timeout is created. The relying party's
	// authenticated calls layer mutual TLS onto a copy of it.
	HTTPClient *http.Client `json:"-" yaml:"-"`

	// Clock is the time statements and tokens are judged and signed at. Not serialized; supplied programmatically. When nil, the
	// system clock.
	Clock func() time.Time `json:"-" yaml:"-"`

	// Documents keep the federation's signed documents between fetches; see [Documents]. Not serialized; supplied
	// programmatically, and required.
	Documents Documents `json:"-" yaml:"-"`

	// Hooks are applied, in order, to a copy of the entity statement each time it is signed, from New's first signing
	// on and before the hooks added by AddEntityStatementHook (see there). A member the statement is required to have
	// may come from them. Not serialized; supplied programmatically.
	Hooks []func(*EntityStatement) error `json:"-" yaml:"-"`

	// Logger receives the failures of Documents, which cost a fetch and nothing else, and the failures of signing the
	// entity statement anew, after which the last one is served until it expires. Not serialized; supplied
	// programmatically. When nil, such failures are dropped silently.
	Logger *slog.Logger `json:"-" yaml:"-"`
}

// RelyingPartyMetadata holds the variable openid_relying_party fields; the OIDF boilerplate is defaulted.
// gemSpec_IDP_FD A_23034-02 asks a registered relying party for keywords (its product type and version), contacts
// (a support address) and organization_name, and A_27505 for ti_features_supported; their content is the
// deployment's to give.
type RelyingPartyMetadata struct {
	ClientName          string      `json:"client_name" yaml:"client_name"`
	RedirectURIs        []string    `json:"redirect_uris" yaml:"redirect_uris"`
	OrganizationName    string      `json:"organization_name,omitzero" yaml:"organization_name,omitempty"`
	LogoURI             string      `json:"logo_uri,omitzero" yaml:"logo_uri,omitempty"`
	Keywords            []string    `json:"keywords,omitzero" yaml:"keywords,omitempty"`
	Contacts            []string    `json:"contacts,omitzero" yaml:"contacts,omitempty"`
	TIFeaturesSupported *TIFeatures `json:"ti_features_supported,omitzero" yaml:"ti_features_supported,omitempty"`
	Scope               string      `json:"scope,omitzero" yaml:"scope,omitempty"`                           // default defaultMetadataScope
	DefaultACRValues    []string    `json:"default_acr_values,omitzero" yaml:"default_acr_values,omitempty"` // default [defaultACRValue]
	// SignedJwksURI, when set, names where ServeSignedJwks publishes the relying party's keys as a signed JWK Set;
	// the openid_relying_party metadata then carries no jwks of its own (gemSpec_IDP_FD A_23034-02).
	SignedJwksURI string `json:"signed_jwks_uri,omitzero" yaml:"signed_jwks_uri,omitempty"`
}

// FederationEntity holds the variable federation_entity metadata.
type FederationEntity struct {
	Name             string   `json:"name,omitzero" yaml:"name,omitempty"`
	OrganizationName string   `json:"organization_name,omitzero" yaml:"organization_name,omitempty"`
	Contacts         []string `json:"contacts,omitzero" yaml:"contacts,omitempty"`
	HomepageURI      string   `json:"homepage_uri,omitzero" yaml:"homepage_uri,omitempty"`
}

const (
	defaultMetadataScope = "openid urn:telematik:display_name urn:telematik:versicherter"
	defaultACRValue      = "gematik-ehealth-loa-high"
)

// knownFedMasters maps a federation-master URL to its published signing JWK, so a config needs only the URL.
// Unlisted masters require RelyingPartyConfig.FedMasterJWK.
var knownFedMasters = map[string]string{
	"https://app-ref.federationmaster.de":  `{"kty":"EC","crv":"P-256","x":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","y":"XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw","kid":"puk_fedmaster_sig","use":"sig","alg":"ES256"}`,
	"https://app-test.federationmaster.de": `{"kty":"EC","crv":"P-256","x":"V8ObgUkjfXonW7XJ4KlPklkB9JiFmN-YlDgWNyqEmHs","y":"ZCV0a2b60P6Ayl8FPqXhSvRIvuKH6zKULksthEtZoGs","kid":"puk_fedmaster_sig","use":"sig","alg":"ES256"}`,
	"https://app.federationmaster.de":      `{"kty":"EC","crv":"P-256","x":"aaxgIv7_eqkDjlwkmduxUthg0eF6aK549sIvzM2nb5I","y":"hg5uKlgltaMBpL57Huhf8Sl4xYf1P5gRfXL-zd_Vbp0","kid":"puk_fedmaster_sig","use":"sig","alg":"ES256"}`,
}

// RelyingParty is this service's entity in the federation: it signs and serves its entity statement and creates
// clients for the federated OpenID providers. Only one built by New serves.
type RelyingParty struct {
	cfg *RelyingPartyConfig
	// fedMaster is the master's entity identifier, from either form of the configuration.
	fedMaster       string
	trustAnchor     *jose.JSONWebKeySet
	keys            Keys
	entityStatement *EntityStatement
	// relyingPartyKeys are the ID token and client keys, inline in the statement or behind signed_jwks_uri.
	relyingPartyKeys *jose.JSONWebKeySet
	federation       *OpenidFederation
	httpClient       *http.Client

	hooksMu sync.Mutex
	hooks   []func(*EntityStatement) error

	// statement and jwks are what Serve and ServeSignedJwks answer with, signed together and replaced whole.
	statement, jwks atomic.Pointer[served]
	// signing holds the one token that lets a caller sign; a buffered channel, so that a wait can end with its
	// context.
	signing chan struct{}
	// stale is set when a hook was added after the last signing.
	stale atomic.Bool
	// refetchedAt is when the documents of an IDP were last refetched past the store, by issuer. Only admitted
	// issuers get an entry, and entries older than refetchInterval are dropped, so the IdP list bounds it.
	refetchMu   sync.Mutex
	refetchedAt map[string]time.Time
	// refetching holds the refetch in flight, by issuer.
	refetching map[string]*refetchFlight

	// retryAt, in Unix nanoseconds, is when a request may try again after a failed signing; zero after a success.
	// Written only by the holder of the signing token.
	retryAt atomic.Int64
}

// Validate reports a missing field of what the relying party publishes and whom it trusts.
func (cfg *RelyingPartyConfig) Validate() error {
	for _, field := range []struct {
		name    string
		present bool
	}{
		{"entity", cfg.Subject != ""},
		{"relying_party.client_name", cfg.RelyingParty.ClientName != ""},
		{"relying_party.redirect_uris", len(cfg.RelyingParty.RedirectURIs) > 0},
	} {
		if !field.present {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	_, err := cfg.fedMasterEntityID()
	return err
}

// wellKnownFederation is the path of an entity configuration below its entity identifier (OpenID Federation 1.1
// section 9).
const wellKnownFederation = "/.well-known/openid-federation"

// fedMasterEntityID is the master's entity identifier: FedMasterURL, or what precedes the well-known path of
// FedMasterEntityStatementURI. Exactly one of the two has to be set.
func (cfg *RelyingPartyConfig) fedMasterEntityID() (string, error) {
	switch {
	case cfg.FedMasterURL != "" && cfg.FedMasterEntityStatementURI != "":
		return "", errors.New("set one of master and master_entity_statement_uri, not both")
	case cfg.FedMasterURL != "":
		return cfg.FedMasterURL, nil
	case cfg.FedMasterEntityStatementURI != "":
		return entityIDOfStatementURI(cfg.FedMasterEntityStatementURI)
	default:
		return "", errors.New("master or master_entity_statement_uri is required")
	}
}

// entityIDOfStatementURI takes the location of an entity configuration as the operator configures it, so that the
// prefix is an entity identifier the master's statement has to name as iss and sub.
func entityIDOfStatementURI(location string) (string, error) {
	const name = "master_entity_statement_uri"
	if _, _, err := checkHTTPSURL(location, maxEntityIdentifierBytes+len(wellKnownFederation)); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if strings.Contains(location, "?") {
		return "", fmt.Errorf("%s has a query", name)
	}
	entityID, found := strings.CutSuffix(location, wellKnownFederation)
	if !found {
		return "", fmt.Errorf("%s does not end in %s", name, wellKnownFederation)
	}
	if err := checkEntityIdentifier(entityID); err != nil {
		return "", fmt.Errorf("%s does not start with an entity identifier", name)
	}
	return entityID, nil
}

// New builds the relying party from cfg and keys and resolves the federation master's entity statement, so the
// master has to be reachable and its statement has to verify. It refuses a configuration without a document store, a gated master without an API
// key ([ErrAPIKeyRequired]) and keys that are not as A_23196 requires (see [Keys]).
func New(ctx context.Context, cfg *RelyingPartyConfig, keys Keys) (*RelyingParty, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	if cfg.Documents == nil {
		return nil, errors.New("config validation failed: a store of federation documents is required")
	}
	if slices.ContainsFunc(cfg.Hooks, func(hook func(*EntityStatement) error) bool { return hook == nil }) {
		return nil, errors.New("config validation failed: a hook is nil")
	}
	if err := keys.check(); err != nil {
		return nil, err
	}
	statementKeys, relyingPartyKeys, err := keys.publishedKeys()
	if err != nil {
		return nil, err
	}

	rp := RelyingParty{cfg: cfg, keys: keys, hooks: slices.Clone(cfg.Hooks)}
	if rp.fedMaster, err = cfg.fedMasterEntityID(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	if err := checkAPIKey(rp.fedMaster, cfg.APIKey); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	rp.trustAnchor, err = cfg.resolveTrustAnchor()
	if err != nil {
		return nil, err
	}

	baseClient := cfg.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// The relying party's authenticated calls (PAR, token) use mutual TLS, and the dev gematik OPs also gate
	// on the federation API key — so layer both onto a copy of the base transport (same x-authorization
	// injection as the federation client), without mutating the caller's.
	mtlsClient := *baseClient
	mtlsClient.CheckRedirect = refuseRedirect
	// GetClientCertificate (not Certificates) so our self-signed client cert is presented
	// unconditionally: self_signed_tls_client_auth means the IDP's CertificateRequest advertises a
	// list of acceptable CA names that does not include our self-signed issuer, and Go would otherwise
	// withhold the cert for not chaining to one of them.
	clientCertificate := keys.Client
	mtlsClient.Transport = AddAPIKeyTransport(transportWithClientCertificate(baseClient.Transport, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &clientCertificate, nil
	}), cfg.APIKey)
	rp.httpClient = &mtlsClient

	rp.entityStatement = &EntityStatement{
		Issuer:   cfg.Subject,
		Subject:  cfg.Subject,
		Metadata: cfg.buildMetadata(),
		Jwks:     &Jwks{Keys: statementKeys},
	}
	rp.relyingPartyKeys = relyingPartyKeys
	// The scopes asked for by default have to be registered, or every login would be refused (servers.md rule 17).
	registered := strings.Fields(rp.entityStatement.Metadata.OpenidRelyingParty.Scope)
	used := cfg.Scopes
	if len(used) == 0 {
		used = defaultOPScopes
	}
	for _, scope := range used {
		if !slices.Contains(registered, scope) {
			return nil, fmt.Errorf("config validation failed: %w: scopes holds one that relying_party.scope lacks", ErrScopeNotRegistered)
		}
	}
	if cfg.RelyingParty.SignedJwksURI == "" {
		rp.entityStatement.Metadata.OpenidRelyingParty.Jwks = &Jwks{Keys: relyingPartyKeys}
	}

	rp.federation, err = NewOpenidFederation(ctx, rp.fedMaster, rp.trustAnchor,
		WithHTTPClient(baseClient), WithAPIKey(cfg.APIKey), WithClock(rp.now), WithDocuments(cfg.Documents), WithLogger(cfg.Logger))
	if err != nil {
		return nil, err
	}

	// Signed at the start, so that a key or a statement that cannot be signed stops it (servers.md rule 17).
	rp.signing = make(chan struct{}, 1)
	if err := rp.sign(ctx); err != nil {
		return nil, fmt.Errorf("sign the entity statement: %w", err)
	}
	return &rp, nil
}

// AddEntityStatementHook registers a function applied to a copy of the entity statement each time it is signed, after
// RelyingPartyConfig.Hooks and the hooks added before it. A hook may change anything in the copy, add members through
// the Extra maps and whole entity types through Metadata.Extra; the relying party's own statement stays as it is. iss,
// sub, iat, exp and authority_hints are set after the hooks, and the statement is checked after them. A hook that
// returns an error fails the signing, and nothing half-built is signed.
//
// Hooks run only when the relying party signs: at New, on Refresh, and when a request finds the served statement due
// for signing anew, which a hook added since makes it. Logins are checked against the statement served, the redirect
// URIs, scope and ID token versions it registers, so a host calls Refresh after adding a hook: what the hook adds is
// served and taken from then on, and a hook that fails is the host's error rather than a log entry. A member the
// statement cannot do without belongs in RelyingPartyConfig.Hooks, since New checks the statement it signs first.
func (rp *RelyingParty) AddEntityStatementHook(h func(*EntityStatement) error) {
	rp.hooksMu.Lock()
	rp.hooks = append(rp.hooks, h)
	rp.hooksMu.Unlock()
	rp.stale.Store(true)
}

// statementWithHooks returns a deep copy of the relying party's statement with the hooks applied.
func (rp *RelyingParty) statementWithHooks() (*EntityStatement, error) {
	rp.hooksMu.Lock()
	hooks := slices.Clone(rp.hooks)
	rp.hooksMu.Unlock()
	es := rp.entityStatement.clone()
	for _, hook := range hooks {
		if err := hook(es); err != nil {
			return nil, fmt.Errorf("entity statement hook: %w", err)
		}
	}
	return es, nil
}

// now is the time the relying party judges and signs at.
func (rp *RelyingParty) now() time.Time {
	if rp != nil && rp.cfg != nil && rp.cfg.Clock != nil {
		return rp.cfg.Clock()
	}
	return time.Now()
}

const (
	// maxStatementLifetime is exp − iat of what the relying party signs. gemSpec_IDP_FedMaster A_28857: "Die maximale
	// Gültigkeitsdauer - gegeben durch die Differenz der Attributwerte exp - iat - darf 24 Stunden nicht
	// überschreiten."
	maxStatementLifetime = 24 * time.Hour
	// statementBackdate puts iat before now, so that a verifier whose clock runs behind takes the statement too.
	statementBackdate = time.Hour
)

// SignEntityStatement returns the entity statement, with the hooks applied, as a JWT signed with the signing
// key. It is backdated one hour and valid for 23 hours from now. A statement that is not this relying party's own
// entity configuration, or that would publish a private key part, is refused with ErrEntityStatement. Each call signs
// anew; Serve answers with a statement signed before.
func (rp *RelyingParty) SignEntityStatement() ([]byte, error) {
	return rp.signEntityStatement(rp.now())
}

func (rp *RelyingParty) signEntityStatement(now time.Time) ([]byte, error) {
	signed, _, err := rp.signStatement(now)
	return signed, err
}

// registration is what a signed statement registers that logins are held to while it is served.
type registration struct {
	redirectURIs []string
	scope        string
	// idTokenVersions are the versions of its ti_features_supported.
	idTokenVersions []string
}

// signStatement signs the statement with the hooks applied and returns what it registers.
func (rp *RelyingParty) signStatement(now time.Time) (signed []byte, registered registration, err error) {
	es, err := rp.statementWithHooks()
	if err != nil {
		return nil, registration{}, err
	}
	issuedAt := now.Add(-statementBackdate)
	// An entity configuration names its entity as issuer and subject (OpenID Federation 1.1 section 3); a hook
	// renames nothing.
	es.Issuer, es.Subject = rp.cfg.Subject, rp.cfg.Subject
	es.IssuedAt = issuedAt.Unix()
	es.ExpiresAt = issuedAt.Add(maxStatementLifetime).Unix()
	es.AuthorityHints = []string{rp.fedMaster}
	if err := rp.checkStatement(es); err != nil {
		return nil, registration{}, err
	}
	payload, err := json.Marshal(es, statementJSON)
	if err != nil {
		return nil, registration{}, fmt.Errorf("marshal entity statement: %w", err)
	}
	if signed, err = rp.signPayload("entity-statement+jwt", payload); err != nil {
		return nil, registration{}, err
	}
	metadata := es.Metadata.OpenidRelyingParty
	return signed, registration{
		redirectURIs:    slices.Clone(metadata.RedirectURIs),
		scope:           metadata.Scope,
		idTokenVersions: slices.Clone(supportedVersions(metadata.TIFeaturesSupported)),
	}, nil
}

// signedJwksClaims keep the shape registered parties get today: a whole JWK Set under "keys", so the array sits at
// keys.keys rather than at the top level of the payload.
type signedJwksClaims struct {
	Issuer    string              `json:"iss"`
	IssuedAt  int64               `json:"iat"`
	ExpiresAt int64               `json:"exp"`
	Keys      *jose.JSONWebKeySet `json:"keys"`
}

// signJwks returns the ID token and client keys as a signed JWK Set, with the lifetime of the statement.
func (rp *RelyingParty) signJwks(now time.Time) ([]byte, error) {
	if err := checkPublicKeys(rp.relyingPartyKeys, "the signed JWKS"); err != nil {
		return nil, err
	}
	issuedAt := now.Add(-statementBackdate)
	payload, err := json.Marshal(signedJwksClaims{
		Issuer:    rp.entityStatement.Subject,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(maxStatementLifetime).Unix(),
		Keys:      rp.relyingPartyKeys,
	}, statementJSON)
	if err != nil {
		return nil, err
	}
	// OpenID Federation 1.1 section 5.2.1, signed_jwks_uri: an explicitly typed JWT, typ jwk-set+jwt.
	return rp.signPayload("jwk-set+jwt", payload)
}

// signPayload signs the payload as a compact JWT with the signing key, under its kid and the given typ. The key signs
// through crypto.Signer, so it may be an HSM's, and only ES256 (A_23196). A payload with a member named d at any depth
// is refused, so that no private key part is ever published, and so is one larger than maxStatementBytes.
func (rp *RelyingParty) signPayload(typ string, payload []byte) ([]byte, error) {
	if isNil(rp.keys.Sign) {
		return nil, errors.New("no signing key")
	}
	if len(payload) > maxStatementBytes {
		return nil, fmt.Errorf("%w: %d bytes, more than %d", ErrEntityStatement, len(payload), maxStatementBytes)
	}
	private, err := hasMemberD(payload)
	if err != nil {
		return nil, err
	}
	if private {
		return nil, fmt.Errorf("%w: a member named d would publish a private key part", ErrEntityStatement)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(rp.keys.Sign)},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", rp.keys.SignKID),
	)
	if err != nil {
		return nil, err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return []byte(compact), nil
}

// ErrIDPNotAdmitted is an issuer that is not on the federation master's signed IdP list.
var ErrIDPNotAdmitted = errors.New("identity provider not admitted")

// Client resolves issuer through the federation master and returns a client for that OpenID provider.
//
// The issuer has to be on the master's signed IdP list (gemSpec_IDP_FedMaster Tabelle 8, which gemSpec_IDP_FD has a
// relying party fetch), byte for byte, before anything is fetched at or about it: the issuer usually comes from a
// request, and a fetch goes only to hosts the trust chain names (servers.md rule 2). Then its entity statement is resolved along the chain from the trust anchor,
// it has to describe an openid_provider whose endpoints are https, and its signed JWKS is fetched. Documents come from
// the store while they verify, else they are fetched.
func (rp *RelyingParty) Client(ctx context.Context, issuer string) (*RelyingPartyClient, error) {
	if err := rp.admit(ctx, issuer); err != nil {
		return nil, err
	}
	resolved, err := rp.resolveProvider(ctx, issuer, false)
	if err != nil {
		return nil, err
	}
	scopes := rp.cfg.Scopes
	if len(scopes) == 0 {
		scopes = defaultOPScopes
	}
	client := &RelyingPartyClient{
		rp:          rp,
		issuer:      issuer,
		scopes:      scopes,
		redirectURI: rp.entityStatement.Metadata.OpenidRelyingParty.RedirectURIs[0],
	}
	client.current.Store(resolved)
	return client, nil
}

// admit refuses an issuer that is not an entry of the master's IdP list. The list and the master's statement are
// fetched from the master only.
func (rp *RelyingParty) admit(ctx context.Context, issuer string) error {
	if err := checkEntityIdentifier(issuer); err != nil {
		return fmt.Errorf("%w: %w", ErrIDPNotAdmitted, err)
	}
	idps, err := rp.federation.FetchIdpList(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(idps, func(idp IdentityProviderInfo) bool { return idp.Issuer == issuer }) {
		return fmt.Errorf("%w: not on the master's IdP list", ErrIDPNotAdmitted)
	}
	return nil
}

// ErrNotAnOpenIDProvider is an admitted entity whose statement does not describe an OpenID provider the relying party
// can log in at.
var ErrNotAnOpenIDProvider = errors.New("not an OpenID provider")

// resolveProvider resolves the entity statement and signed JWKS of an admitted issuer; fresh fetches them past the
// store.
func (rp *RelyingParty) resolveProvider(ctx context.Context, issuer string, fresh bool) (*provider, error) {
	op, err := rp.federation.entityStatement(ctx, issuer, fresh)
	if err != nil {
		return nil, err
	}
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, fmt.Errorf("%w: the statement has no openid_provider metadata", ErrNotAnOpenIDProvider)
	}
	metadata := op.Metadata.OpenidProvider
	// OpenID Connect Discovery 1.0 section 4.3: the issuer the provider names is the one it was resolved as.
	if metadata.Issuer != issuer {
		return nil, fmt.Errorf("%w: openid_provider names another issuer", ErrNotAnOpenIDProvider)
	}
	for _, endpoint := range []struct{ name, location string }{
		{"authorization_endpoint", metadata.AuthorizationEndpoint},
		{"pushed_authorization_request_endpoint", metadata.PushedAuthorizationRequestEndpoint},
		{"token_endpoint", metadata.TokenEndpoint},
		{"signed_jwks_uri", metadata.SignedJwksURI},
	} {
		if err := checkFederationURL(endpoint.location); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrNotAnOpenIDProvider, endpoint.name, err)
		}
	}
	jwks, err := rp.federation.signedJwks(ctx, op, fresh)
	if err != nil {
		return nil, err
	}
	return &provider{op: op, metadata: metadata, jwks: jwks}, nil
}

// resolveTrustAnchor returns the federation master's signing key set: the explicit FedMasterJWK, else the
// built-in JWK of the master's entity identifier.
func (cfg *RelyingPartyConfig) resolveTrustAnchor() (*jose.JSONWebKeySet, error) {
	if cfg.FedMasterJWK != nil && cfg.FedMasterJWK.Key != nil {
		set, err := cfg.FedMasterJWK.AsSet()
		if err != nil {
			return nil, fmt.Errorf("master_jwk: %w", err)
		}
		return set.Keys, nil
	}
	entityID, err := cfg.fedMasterEntityID()
	if err != nil {
		return nil, err
	}
	known, ok := knownFedMasters[entityID]
	if !ok {
		return nil, fmt.Errorf("no built-in trust anchor for the master %q; set master_jwk", entityID)
	}
	key, err := openid.ParseKey([]byte(known))
	if err != nil {
		return nil, fmt.Errorf("parse built-in fed master jwk: %w", err)
	}
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*key}}, nil
}

// buildMetadata assembles the entity-statement metadata from the deployment-specific config plus the
// invariant gematik OIDF defaults.
func (cfg *RelyingPartyConfig) buildMetadata() *Metadata {
	rp := cfg.RelyingParty
	scope := rp.Scope
	if scope == "" {
		scope = defaultMetadataScope
	}
	acr := rp.DefaultACRValues
	if len(acr) == 0 {
		acr = []string{defaultACRValue}
	}
	return &Metadata{
		OpenidRelyingParty: &OpenIDRelyingPartyMetadata{ //nolint:gosec // TokenEndpointAuthMethod holds the public name of an authentication method, not a credential
			ClientName:                         rp.ClientName,
			RedirectURIs:                       rp.RedirectURIs,
			OrganizationName:                   rp.OrganizationName,
			LogoURI:                            rp.LogoURI,
			Keywords:                           rp.Keywords,
			Contacts:                           rp.Contacts,
			TIFeaturesSupported:                rp.TIFeaturesSupported,
			Scope:                              scope,
			DefaultACRValues:                   acr,
			SignedJwksURI:                      rp.SignedJwksURI,
			ResponseTypes:                      []string{"code"},
			ClientRegistrationTypes:            []string{"automatic"},
			GrantTypes:                         []string{"authorization_code"},
			RequirePushedAuthorizationRequests: true,
			TokenEndpointAuthMethod:            "self_signed_tls_client_auth",
			IDTokenSignedResponseAlg:           "ES256",
			IDTokenEncryptedResponseAlg:        "ECDH-ES",
			IDTokenEncryptedResponseEnc:        "A256GCM",
		},
		FederationEntity: &FederationEntityMetadata{
			Name:             cfg.FederationEntity.Name,
			OrganizationName: cfg.FederationEntity.OrganizationName,
			Contacts:         cfg.FederationEntity.Contacts,
			HomepageURI:      cfg.FederationEntity.HomepageURI,
		},
	}
}

// transportWithClientCertificate clones the base transport (or http.DefaultTransport when the base is nil or
// not a *http.Transport) and adds the client certificate to a copy of its TLS configuration, so mutual TLS is
// layered onto the chosen client without mutating it. The base's verification stays whole: its roots, versions
// and VerifyConnection, the web profile's when the host hands one in, never the system's defaults instead.
func transportWithClientCertificate(rt http.RoundTripper, certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) http.RoundTripper {
	base, ok := transportOrDefault(rt).(*http.Transport)
	if !ok {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.GetClientCertificate = certificate
	return t
}

// Federation returns the client of this relying party's federation master.
func (rp *RelyingParty) Federation() *OpenidFederation {
	return rp.federation
}

// refetchTimeout bounds a refetch, which runs past the context of the exchange that started it.
const refetchTimeout = 30 * time.Second

// refetchInterval is how long after a refetch of an IDP's documents past the store another one is refused: an ID token
// is the IDP's to send, but anyone can send a token with a made-up kid, and each would otherwise cost the federation
// three fetches.
const refetchInterval = time.Minute

// refetchFlight is one refetch of an IDP's documents that concurrent exchanges wait for.
type refetchFlight struct {
	done     chan struct{}
	resolved *provider
	err      error
}

// refetchProvider resolves the documents of an admitted issuer anew. Past the store when no refetch of it ran within
// refetchInterval; an exchange that finds one in flight waits for it as long as its context lets it. When the limiter
// refuses, or the refetch it waited for failed, it resolves from the store, which costs no fetch while the kept
// documents verify and holds what a refetch within the minute kept.
//
// The refetch serves every exchange waiting for it, the one that started it included, so it runs in a goroutine of
// its own on a context bounded by refetchTimeout, and always ends. Each exchange waits for it as long as its own
// context lets it. A refetch that failed still counts against the minute: A_22861 asks for one refetch, and the store
// serves meanwhile.
func (rp *RelyingParty) refetchProvider(ctx context.Context, issuer string) (*provider, error) {
	rp.refetchMu.Lock()
	call, inFlight := rp.refetching[issuer]
	switch {
	case inFlight:
		rp.refetchMu.Unlock()
	case !rp.mayRefetchLocked(issuer):
		rp.refetchMu.Unlock()
		return rp.resolveProvider(ctx, issuer, false)
	default:
		call = &refetchFlight{done: make(chan struct{}), err: errors.New("the refetch did not finish")}
		if rp.refetching == nil {
			rp.refetching = make(map[string]*refetchFlight)
		}
		rp.refetching[issuer] = call
		rp.refetchMu.Unlock()
		go rp.refetch(context.WithoutCancel(ctx), issuer, call)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
	}
	if call.err == nil {
		return call.resolved, nil
	}
	return rp.resolveProvider(ctx, issuer, false)
}

// refetch resolves the documents of issuer past the store for everyone waiting on call, within refetchTimeout, and
// releases them.
func (rp *RelyingParty) refetch(ctx context.Context, issuer string, call *refetchFlight) {
	ctx, cancel := context.WithTimeout(ctx, refetchTimeout)
	defer cancel()
	defer func() {
		rp.refetchMu.Lock()
		delete(rp.refetching, issuer)
		rp.refetchMu.Unlock()
		close(call.done)
	}()
	call.resolved, call.err = rp.resolveProvider(ctx, issuer, true)
}

// mayRefetchLocked reports whether the documents of issuer may be refetched past the store now, and if so counts the
// refetch. The caller holds refetchMu.
func (rp *RelyingParty) mayRefetchLocked(issuer string) bool {
	now := rp.now()
	if rp.refetchedAt == nil {
		rp.refetchedAt = make(map[string]time.Time)
	}
	for known, at := range rp.refetchedAt {
		if now.Sub(at) >= refetchInterval {
			delete(rp.refetchedAt, known)
		}
	}
	if _, recent := rp.refetchedAt[issuer]; recent {
		return false
	}
	rp.refetchedAt[issuer] = now
	return true
}

// registered is what the statement served now registers, hooks applied: the redirect_uris an IDP compares a login's
// redirect_uri with, which a host's hook may add to, the scope a login may ask for and the ID token versions of its
// ti_features_supported. A relying party that serves nothing, which is one not built by New, registers nothing, and
// every login is refused.
func (rp *RelyingParty) registered() registration {
	if statement := rp.statement.Load(); statement != nil {
		return statement.registered
	}
	return registration{}
}

// ClientID returns the entity identifier, which is the OIDF client_id.
func (rp *RelyingParty) ClientID() string {
	return rp.entityStatement.Subject
}
