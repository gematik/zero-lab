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
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gopkg.in/yaml.v3"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// defaultOPScopes are requested from an OpenID provider when RelyingPartyConfig.Scopes is unset — the
// minimal identity set (display name + insured/KVNR).
var defaultOPScopes = []string{"openid", "urn:telematik:display_name", "urn:telematik:versicherter"}

// RelyingPartyConfig configures a gematik OpenID Federation relying party. Only deployment-specific values
// are required; the invariant gematik OIDF metadata (response_types, grant_types, client_registration_types,
// token_endpoint_auth_method, id_token algorithms, PAR) is filled in by buildMetadata.
type RelyingPartyConfig struct {
	BaseDir string `yaml:"-"`

	// Subject is this relying party's entity identifier — its own public URL — and also the entity
	// statement's iss/sub and the OIDF client_id.
	Subject string `yaml:"sub"`

	// FedMasterURL is the federation master. Its trust-anchor signing key is resolved from a built-in table
	// of known gematik masters (see knownFedMasters); set FedMasterJWK to override or for an unlisted master.
	FedMasterURL string `yaml:"fed_master_url"`
	FedMasterJWK *Jwk   `yaml:"fed_master_jwk,omitempty"`

	// SignKey signs the entity statement; EncKey decrypts the JWE id_token; ClientKey authenticates the
	// self_signed_tls_client_auth mTLS calls (its cert_pem_path is required). Each is a KeyConfig.
	SignKey   KeyConfig `yaml:"sign_key"`
	EncKey    KeyConfig `yaml:"enc_key"`
	ClientKey KeyConfig `yaml:"client_key"`

	// RelyingParty + FederationEntity are the deployment-specific entity-statement metadata; the rest is
	// defaulted.
	RelyingParty     RelyingPartyMetadata `yaml:"relying_party"`
	FederationEntity FederationEntity     `yaml:"federation_entity"`

	// Scopes requested from the OpenID provider's authorization endpoint (which identity claims it returns).
	// When empty, defaultOPScopes is used.
	Scopes []string `yaml:"scopes,omitempty"`

	// HTTPClient is the base client for federation and relying-party calls. Not serialized; supplied
	// programmatically. When nil, a client with a default timeout is created. The relying party's
	// authenticated calls layer mutual TLS onto a copy of it.
	HTTPClient *http.Client `yaml:"-"`
}

// KeyConfig sources one key. Provide exactly one of KeyPEMPath (a PEM private-key file), JWKPath (a JWK
// file), or JWK (an inline JWK). CertPEMPath is the optional X.509 certificate (PEM) bound to the key —
// required for the client key (mTLS). The key id is Kid when set, otherwise the RFC 7638 SHA-256 thumbprint;
// a relying party already registered with a federation master MUST set Kid to the registered key id, or the
// OP cannot match the signing key (it looks it up by kid in the jwks the master vouches for).
type KeyConfig struct {
	KeyPEMPath  string         `yaml:"key_pem_path,omitempty"`
	CertPEMPath string         `yaml:"cert_pem_path,omitempty"`
	JWKPath     string         `yaml:"jwk_path,omitempty"`
	JWK         map[string]any `yaml:"jwk,omitempty"`
	Kid         string         `yaml:"kid,omitempty"`
}

// RelyingPartyMetadata holds the variable openid_relying_party fields; the OIDF boilerplate is defaulted.
type RelyingPartyMetadata struct {
	ClientName       string   `yaml:"client_name"`
	RedirectURIs     []string `yaml:"redirect_uris"`
	OrganizationName string   `yaml:"organization_name,omitempty"`
	LogoURI          string   `yaml:"logo_uri,omitempty"`
	Scope            string   `yaml:"scope,omitempty"`              // default defaultMetadataScope
	DefaultACRValues []string `yaml:"default_acr_values,omitempty"` // default [defaultACRValue]
	SignedJwksURI    string   `yaml:"signed_jwks_uri,omitempty"`
}

// FederationEntity holds the variable federation_entity metadata.
type FederationEntity struct {
	Name        string   `yaml:"name,omitempty"`
	Contacts    []string `yaml:"contacts,omitempty"`
	HomepageURI string   `yaml:"homepage_uri,omitempty"`
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
// clients for the federated OpenID providers.
type RelyingParty struct {
	cfg              *RelyingPartyConfig
	trustAnchor      jwk.Set
	sigPrivateKey    jwk.Key
	signKid          string
	encPrivateKey    jwk.Key
	clientPrivateKey jwk.Key
	entityStatement  *EntityStatement
	federation       *OpenidFederation
	httpClient       *http.Client
	hooks            []func(*EntityStatement)
}

// LoadRelyingPartyConfig reads a RelyingPartyConfig from the YAML file at path; relative key paths resolve against
// the file's directory. NewRelyingPartyFromConfig validates the result.
func LoadRelyingPartyConfig(path string) (*RelyingPartyConfig, error) {
	yamlData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", path, err)
	}
	cfg := new(RelyingPartyConfig)
	err = yaml.Unmarshal(yamlData, cfg)
	cfg.BaseDir = filepath.Dir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file '%s': %w", path, err)
	}
	return cfg, nil
}

// NewRelyingPartyFromConfigFile builds a relying party from the YAML configuration file at path.
func NewRelyingPartyFromConfigFile(path string) (*RelyingParty, error) {
	cfg, err := LoadRelyingPartyConfig(path)
	if err != nil {
		return nil, err
	}
	return NewRelyingPartyFromConfig(cfg)
}

// Validate reports a missing required field. What needs I/O is checked when the keys are loaded.
func (cfg *RelyingPartyConfig) Validate() error {
	for _, field := range []struct {
		name    string
		present bool
	}{
		{"sub", cfg.Subject != ""},
		{"fed_master_url", cfg.FedMasterURL != ""},
		{"sign_key", !reflect.ValueOf(cfg.SignKey).IsZero()},
		{"enc_key", !reflect.ValueOf(cfg.EncKey).IsZero()},
		{"client_key", !reflect.ValueOf(cfg.ClientKey).IsZero()},
		{"relying_party.client_name", cfg.RelyingParty.ClientName != ""},
		{"relying_party.redirect_uris", len(cfg.RelyingParty.RedirectURIs) > 0},
	} {
		if !field.present {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	return nil
}

// NewRelyingPartyFromConfig validates cfg, loads its keys and fetches the federation master's entity statement,
// so the master has to be reachable and its statement has to verify for this to succeed.
func NewRelyingPartyFromConfig(cfg *RelyingPartyConfig) (*RelyingParty, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	rp := RelyingParty{cfg: cfg}

	rp.trustAnchor, err = cfg.resolveTrustAnchor()
	if err != nil {
		return nil, err
	}

	if cfg.ClientKey.CertPEMPath == "" {
		return nil, errors.New("client_key.cert_pem_path is required (mTLS)")
	}

	var sigPublicKey, encPublicKey, clientPublicKey jwk.Key
	if rp.sigPrivateKey, sigPublicKey, rp.signKid, err = loadKeyConfig(cfg.SignKey, cfg.BaseDir, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("sign_key: %w", err)
	}
	if rp.encPrivateKey, encPublicKey, _, err = loadKeyConfig(cfg.EncKey, cfg.BaseDir, jwk.ForEncryption); err != nil {
		return nil, fmt.Errorf("enc_key: %w", err)
	}
	if rp.clientPrivateKey, clientPublicKey, _, err = loadKeyConfig(cfg.ClientKey, cfg.BaseDir, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("client_key: %w", err)
	}

	tlsCert, err := tlsCertFromKey(rp.clientPrivateKey, rp.absPath(cfg.ClientKey.CertPEMPath))
	if err != nil {
		return nil, fmt.Errorf("build mTLS client cert: %w", err)
	}

	baseClient := cfg.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// The relying party's authenticated calls (PAR, token) use mutual TLS, and the dev gematik OPs also gate
	// on the federation API key — so layer both onto a copy of the base transport (same x-authorization
	// injection as the federation client), without mutating the caller's.
	mtlsClient := *baseClient
	mtlsClient.Transport = AddAPIKeyTransport(transportWithTLS(baseClient.Transport, &tls.Config{
		// GetClientCertificate (not Certificates) so our self-signed client cert is presented
		// unconditionally: self_signed_tls_client_auth means the IDP's CertificateRequest advertises a
		// list of acceptable CA names that does not include our self-signed issuer, and Go would otherwise
		// withhold the cert for not chaining to one of them.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tlsCert, nil
		},
	}))
	rp.httpClient = &mtlsClient

	rp.entityStatement = &EntityStatement{
		Issuer:   cfg.Subject,
		Subject:  cfg.Subject,
		Metadata: cfg.buildMetadata(),
	}

	rp.entityStatement.Jwks = &Jwks{Keys: jwk.NewSet()}
	if err := rp.entityStatement.Jwks.Keys.AddKey(sigPublicKey); err != nil {
		return nil, fmt.Errorf("sign_key: %w", err)
	}

	entityJwks := jwk.NewSet()
	if err := entityJwks.AddKey(encPublicKey); err != nil {
		return nil, fmt.Errorf("enc_key: %w", err)
	}
	if err := entityJwks.AddKey(clientPublicKey); err != nil {
		return nil, fmt.Errorf("client_key: %w", err)
	}

	rp.entityStatement.Metadata.OpenidRelyingParty.Jwks = &Jwks{Keys: entityJwks}

	rp.federation, err = NewOpenidFederation(cfg.FedMasterURL, rp.trustAnchor, WithHTTPClient(baseClient))
	if err != nil {
		return nil, err
	}

	return &rp, nil
}

func (rp *RelyingParty) absPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(rp.cfg.BaseDir, path)
}

// AddEntityStatementHook registers a function applied to a copy of the entity statement on every
// SignEntityStatement call, in registration order. A hook may mutate the copy (e.g. append redirect_uris)
// and never affects the relying party's base statement. This lets a consumer inject values into the served
// entity statement without oidf depending on it; add more hooks the same way for future needs.
func (rp *RelyingParty) AddEntityStatementHook(h func(*EntityStatement)) {
	rp.hooks = append(rp.hooks, h)
}

// entityStatementForRequest returns a copy of the base entity statement with all hooks applied. Only the
// fields a hook may mutate (metadata.openid_relying_party.redirect_uris) are deep-copied; the rest shares
// the base's pointers, which is safe because hooks only append to the cloned slice — so repeated calls do
// not accumulate.
func (rp *RelyingParty) entityStatementForRequest() *EntityStatement {
	es := *rp.entityStatement
	if md := rp.entityStatement.Metadata; md != nil {
		mdCopy := *md
		if orp := md.OpenidRelyingParty; orp != nil {
			orpCopy := *orp
			orpCopy.RedirectURIs = slices.Clone(orp.RedirectURIs)
			mdCopy.OpenidRelyingParty = &orpCopy
		}
		es.Metadata = &mdCopy
	}
	for _, h := range rp.hooks {
		h(&es)
	}
	return &es
}

// SignEntityStatement returns the entity statement, with the hooks applied, as a JWT signed with the signing
// key. It is backdated one hour and valid for 23 hours from now.
func (rp *RelyingParty) SignEntityStatement() ([]byte, error) {
	es := rp.entityStatementForRequest()

	token, err := jwt.NewBuilder().
		Issuer(es.Issuer).
		Subject(es.Subject).
		IssuedAt(time.Now().Add(-1*time.Hour)). // backdate token to avoid clock skew
		Expiration(time.Now().Add(time.Hour*23)).
		Claim("jwks", es.Jwks.Keys).
		Claim("authority_hints", []string{rp.cfg.FedMasterURL}).
		Claim("metadata", es.Metadata).
		Build()
	if err != nil {
		return nil, err
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, rp.signKid); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.TypeKey, "entity-statement+jwt"); err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(token,
		jwt.WithKey(
			jwa.ES256(),
			rp.sigPrivateKey,
			jws.WithProtectedHeaders(headers),
		),
	)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

// Serve is the HTTP handler of the entity statement endpoint.
func (rp *RelyingParty) Serve(w http.ResponseWriter, _ *http.Request) {
	signed, err := rp.SignEntityStatement()
	if err != nil {
		slog.Error("unable to sign entity statement", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	if _, err := w.Write(signed); err != nil {
		slog.Warn("unable to write entity statement", "error", err)
	}
}

// ServeSignedJwks is the HTTP handler of signed_jwks_uri: the encryption and client keys of the relying party as
// a signed JWT, backdated one hour and valid for 23 hours from now.
func (rp *RelyingParty) ServeSignedJwks(w http.ResponseWriter, r *http.Request) {
	token, err := jwt.NewBuilder().
		Issuer(rp.entityStatement.Subject).
		IssuedAt(time.Now().Add(-1*time.Hour)). // backdate token to avoid clock skew
		Expiration(time.Now().Add(time.Hour*23)).
		Claim("keys", rp.entityStatement.Metadata.OpenidRelyingParty.Jwks.Keys).
		Build()
	if err != nil {
		slog.Error("unable to build token", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, rp.signKid); err != nil {
		slog.Error("unable to set token header", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := headers.Set(jws.TypeKey, "jwk-set+json"); err != nil {
		slog.Error("unable to set token header", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	signed, err := jwt.Sign(token,
		jwt.WithKey(
			jwa.ES256(),
			rp.sigPrivateKey,
			jws.WithProtectedHeaders(headers),
		),
	)
	if err != nil {
		slog.Error("unable to sign token", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/jwk-set+jwt")
	if _, err := w.Write(signed); err != nil {
		slog.Warn("unable to write signed jwks", "error", err)
		return
	}

	slog.Info("served signed jwks", "remote_addr", r.RemoteAddr)
}

type pushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// NewClient resolves issuer through the federation master and returns a client for that OpenID provider. Each
// call fetches the provider's entity statement and signed JWKS anew.
func (rp *RelyingParty) NewClient(issuer string) (oidc.Client, error) {
	op, err := rp.federation.FetchEntityStatement(issuer)
	if err != nil {
		return nil, err
	}

	// TODO: check if entity is openid provider
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, errors.New("no openid provider metadata found")
	}

	metadata := op.Metadata.OpenidProvider

	jwks, err := rp.federation.FetchSignedJwks(op)
	if err != nil {
		return nil, err
	}

	scopes := rp.cfg.Scopes
	if len(scopes) == 0 {
		scopes = defaultOPScopes
	}

	return &RelyingPartyClient{
		rp:          rp,
		op:          op,
		scopes:      scopes,
		redirectURI: rp.entityStatement.Metadata.OpenidRelyingParty.RedirectURIs[0],
		metadata:    metadata,
		jwks:        jwks,
	}, nil
}

// Loads the certificate from specified path. The certificate must be in PEM format.
// Returns the certificate bytes in DER encoding.
func loadCertBytesFromPem(certPath string) ([]byte, error) {
	certDataPem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}
	certDataDer, _ := pem.Decode(certDataPem)
	if certDataDer == nil {
		return nil, fmt.Errorf("failed to decode cert file %s: %w", certPath, err)
	}
	return certDataDer.Bytes, nil
}

// Loads the private key from the given path
// and adds the certificate chain if certPath is not empty.
// loadKeyConfig loads one key (PEM file, JWK file, or inline JWK) for the given usage, returning the private
// key, the matching public key, and the key id. The kid is KeyConfig.Kid when set, otherwise the RFC 7638
// SHA-256 thumbprint. When KeyConfig.CertPEMPath is set the public key carries the X.509 cert chain.
func loadKeyConfig(kc KeyConfig, baseDir string, keyUsage jwk.KeyUsageType) (jwk.Key, jwk.Key, string, error) {
	privateKey, err := parseKeySource(kc, baseDir)
	if err != nil {
		return nil, nil, "", err
	}

	kid := kc.Kid
	if kid == "" {
		tp, err := privateKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, nil, "", fmt.Errorf("compute key thumbprint: %w", err)
		}
		kid = base64.RawURLEncoding.EncodeToString(tp)
	}

	if err := privateKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, "", fmt.Errorf("set key id: %w", err)
	}
	if err := privateKey.Set(jwk.KeyUsageKey, keyUsage); err != nil {
		return nil, nil, "", fmt.Errorf("set key usage: %w", err)
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("derive public key: %w", err)
	}
	if err := publicKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, "", fmt.Errorf("set key id: %w", err)
	}
	if err := publicKey.Set(jwk.KeyUsageKey, keyUsage); err != nil {
		return nil, nil, "", fmt.Errorf("set key usage: %w", err)
	}
	if keyUsage == jwk.ForEncryption {
		publicKey.Set(jwk.AlgorithmKey, jwa.ECDH_ES) //nolint:errcheck,gosec // TASK-183: always fails: passes the function, not its value, so no alg is published
	} else {
		publicKey.Set(jwk.AlgorithmKey, jwa.ES256) //nolint:errcheck,gosec // TASK-183: always fails: passes the function, not its value, so no alg is published
	}

	if kc.CertPEMPath != "" {
		certDataDer, err := loadCertBytesFromPem(joinBase(baseDir, kc.CertPEMPath))
		if err != nil {
			return nil, nil, "", err
		}
		var certChain cert.Chain
		if err := certChain.AddString(base64.StdEncoding.EncodeToString(certDataDer)); err != nil {
			return nil, nil, "", fmt.Errorf("add cert to chain: %w", err)
		}
		if err := publicKey.Set(jwk.X509CertChainKey, &certChain); err != nil {
			return nil, nil, "", fmt.Errorf("set cert chain: %w", err)
		}
	}

	return privateKey, publicKey, kid, nil
}

// parseKeySource parses a private key from exactly one of pem_path, jwk_path, or an inline jwk.
func parseKeySource(kc KeyConfig, baseDir string) (jwk.Key, error) {
	switch {
	case kc.KeyPEMPath != "":
		data, err := os.ReadFile(joinBase(baseDir, kc.KeyPEMPath))
		if err != nil {
			return nil, fmt.Errorf("read key_pem_path %q: %w", kc.KeyPEMPath, err)
		}
		return jwk.ParseKey(data, jwk.WithPEM(true))
	case kc.JWKPath != "":
		data, err := os.ReadFile(joinBase(baseDir, kc.JWKPath))
		if err != nil {
			return nil, fmt.Errorf("read jwk_path %q: %w", kc.JWKPath, err)
		}
		return jwk.ParseKey(data)
	case len(kc.JWK) > 0:
		data, err := json.Marshal(kc.JWK)
		if err != nil {
			return nil, fmt.Errorf("marshal inline jwk: %w", err)
		}
		return jwk.ParseKey(data)
	default:
		return nil, errors.New("provide one of key_pem_path, jwk_path, or jwk")
	}
}

func joinBase(baseDir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

// tlsCertFromKey builds the mTLS client certificate from the parsed client private key + the PEM cert, so
// the client key may come from any source (PEM, JWK, inline) rather than only a PEM file pair.
func tlsCertFromKey(clientPrivateKey jwk.Key, certPEMPath string) (tls.Certificate, error) {
	certDER, err := loadCertBytesFromPem(certPEMPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	var ecKey ecdsa.PrivateKey
	if err := jwk.Export(clientPrivateKey, &ecKey); err != nil {
		return tls.Certificate{}, fmt.Errorf("export client private key: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: &ecKey}, nil
}

// resolveTrustAnchor returns the federation master's signing key set: the explicit FedMasterJWK, else the
// built-in JWK for a known FedMasterURL.
func (cfg *RelyingPartyConfig) resolveTrustAnchor() (jwk.Set, error) {
	if cfg.FedMasterJWK != nil && cfg.FedMasterJWK.Key != nil {
		set, err := cfg.FedMasterJWK.AsSet()
		if err != nil {
			return nil, fmt.Errorf("fed_master_jwk: %w", err)
		}
		return set.Keys, nil
	}
	known, ok := knownFedMasters[cfg.FedMasterURL]
	if !ok {
		return nil, fmt.Errorf("no built-in trust anchor for fed_master_url %q; set fed_master_jwk", cfg.FedMasterURL)
	}
	key, err := jwk.ParseKey([]byte(known))
	if err != nil {
		return nil, fmt.Errorf("parse built-in fed master jwk: %w", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, fmt.Errorf("add built-in fed master jwk: %w", err)
	}
	return set, nil
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
			Name:        cfg.FederationEntity.Name,
			Contacts:    cfg.FederationEntity.Contacts,
			HomepageURI: cfg.FederationEntity.HomepageURI,
		},
	}
}

// transportWithTLS clones the base transport (or http.DefaultTransport when the base is nil or not a
// *http.Transport) and applies the given TLS config, so mutual TLS is layered onto the chosen client
// without mutating it.
func transportWithTLS(rt http.RoundTripper, tlsConfig *tls.Config) http.RoundTripper {
	base, ok := transportOrDefault(rt).(*http.Transport)
	if !ok {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	t.TLSClientConfig = tlsConfig
	return t
}

// Federation returns the client of this relying party's federation master.
func (rp *RelyingParty) Federation() *OpenidFederation {
	return rp.federation
}

// ClientID returns the entity identifier, which is the OIDF client_id.
func (rp *RelyingParty) ClientID() string {
	return rp.entityStatement.Subject
}
