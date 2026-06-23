package oidf

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gopkg.in/yaml.v3"
)

// defaultOPScopes are requested from an OpenID provider when RelyingPartyConfig.Scopes is unset — the
// minimal identity set (display name + insured/KVNR).
var defaultOPScopes = []string{"openid", "urn:telematik:display_name", "urn:telematik:versicherter"}

type RelyingPartyConfig struct {
	BaseDir              string         `yaml:"-"`
	Subject              string         `yaml:"sub" validate:"required"`
	FedMasterURL         string         `yaml:"fed_master_url" validate:"required"`
	FedMasterJwk         Jwk            `yaml:"fed_master_jwk" validate:"required"`
	SignKid              string         `yaml:"sign_kid" validate:"required"`
	SignPrivateKeyPath   string         `yaml:"sign_private_key_path" validate:"required"`
	EncKid               string         `yaml:"enc_kid" validate:"required"`
	EncPrivateKeyPath    string         `yaml:"enc_private_key_path" validate:"required"`
	ClientKid            string         `yaml:"client_kid" validate:"required"`
	ClientPrivateKeyPath string         `yaml:"client_private_key_path" validate:"required"`
	ClientCertPath       string         `yaml:"client_cert_path" validate:"required"`
	MetadataTemplate     map[string]any `yaml:"metadata_template" validate:"required"`
	// Scopes requested from the OpenID provider's authorization endpoint — the scopes that determine
	// which identity claims (name, KVNR, …) the provider returns. When empty, defaultOPScopes is used.
	Scopes               []string       `yaml:"scopes"`

	// HTTPClient is the base client for federation and relying-party calls. Not serialized; supplied
	// programmatically. When nil, a client with a default timeout is created. The relying party's
	// authenticated calls layer mutual TLS onto a copy of it.
	HTTPClient *http.Client `yaml:"-"`
}

type RelyingParty struct {
	cfg              *RelyingPartyConfig
	trustAnchor      jwk.Set
	sigPrivateKey    jwk.Key
	encPrivateKey    jwk.Key
	clientPrivateKey jwk.Key
	entityStatement  *EntityStatement
	federation       *OpenidFederation
	httpClient       *http.Client
}

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

func NewRelyingPartyFromConfigFile(path string) (*RelyingParty, error) {
	cfg, err := LoadRelyingPartyConfig(path)
	if err != nil {
		return nil, err
	}
	return NewRelyingPartyFromConfig(cfg)
}

func NewRelyingPartyFromConfig(cfg *RelyingPartyConfig) (*RelyingParty, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := fld.Tag.Get("yaml")
		if name == "" {
			name = fld.Name
		}
		return name
	})
	err := validate.Struct(cfg)
	if err != nil {
		slog.Error("config validation failed", "error", err, "config", fmt.Sprintf("%+v", cfg))
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	rp := RelyingParty{
		cfg:         cfg,
		trustAnchor: cfg.FedMasterJwk.AsSet().Keys,
	}

	var sigPublicKey jwk.Key
	rp.sigPrivateKey, sigPublicKey, err = loadKeys(rp.absPath(cfg.SignPrivateKeyPath), cfg.SignKid, jwk.ForSignature, "")
	if err != nil {
		return nil, err
	}

	var encPublicKey jwk.Key
	rp.encPrivateKey, encPublicKey, err = loadKeys(rp.absPath(cfg.EncPrivateKeyPath), cfg.EncKid, jwk.ForEncryption, "")
	if err != nil {
		return nil, err
	}

	var clientPublicKey jwk.Key
	rp.clientPrivateKey, clientPublicKey, err = loadKeys(rp.absPath(cfg.ClientPrivateKeyPath), cfg.ClientKid, jwk.ForSignature, rp.absPath(cfg.ClientCertPath))
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.LoadX509KeyPair(rp.absPath(cfg.ClientCertPath), rp.absPath(cfg.ClientPrivateKeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to load tls cert: %w", err)
	}

	baseClient := cfg.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// the relying party's authenticated calls use mutual TLS; derive that client from the base
	// without mutating the caller's
	mtlsClient := *baseClient
	mtlsClient.Transport = transportWithTLS(baseClient.Transport, &tls.Config{
		// GetClientCertificate (not Certificates) so our self-signed client cert is presented
		// unconditionally: self_signed_tls_client_auth means the IDP's CertificateRequest advertises a
		// list of acceptable CA names that does not include our self-signed issuer, and Go would otherwise
		// withhold the cert for not chaining to one of them.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tlsCert, nil
		},
	})
	rp.httpClient = &mtlsClient

	metadata, err := templateToMetadata(cfg.MetadataTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to convert metadata template: %w", err)
	}

	if metadata.OpenidRelyingParty == nil {
		return nil, fmt.Errorf("template must contain openid_relying_party")
	}

	rp.entityStatement = &EntityStatement{
		Issuer:   cfg.Subject,
		Subject:  cfg.Subject,
		Metadata: metadata,
	}

	rp.entityStatement.Jwks = &Jwks{Keys: jwk.NewSet()}
	rp.entityStatement.Jwks.Keys.AddKey(sigPublicKey)

	entityJwks := jwk.NewSet()
	entityJwks.AddKey(encPublicKey)
	entityJwks.AddKey(clientPublicKey)

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

func (rp *RelyingParty) SignEntityStatement() ([]byte, error) {

	token, err := jwt.NewBuilder().
		Issuer(rp.entityStatement.Issuer).
		Subject(rp.entityStatement.Subject).
		IssuedAt(time.Now().Add(-1*time.Hour)). // backdate token to avoid clock skew
		Expiration(time.Now().Add(time.Hour*23)).
		Claim("jwks", rp.entityStatement.Jwks.Keys).
		Claim("authority_hints", []string{rp.cfg.FedMasterURL}).
		Claim("metadata", rp.entityStatement.Metadata).
		Build()

	if err != nil {
		return nil, err
	}

	headers := jws.NewHeaders()
	headers.Set(jws.KeyIDKey, rp.cfg.SignKid)
	headers.Set(jws.TypeKey, "entity-statement+jwt")

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

func (rp *RelyingParty) Serve(w http.ResponseWriter, r *http.Request) {
	signed, err := rp.SignEntityStatement()
	if err != nil {
		slog.Error("unable to sign entity statement", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	w.Write(signed)
	slog.Info("served entity statement", "remote_addr", r.RemoteAddr)
}

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
	headers.Set(jws.KeyIDKey, rp.cfg.SignKid)
	headers.Set(jws.TypeKey, "jwk-set+json")

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
	w.Write(signed)

	slog.Info("served signed jwks", "remote_addr", r.RemoteAddr)
}

type pushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (rp *RelyingParty) NewClient(issuer string) (oidc.Client, error) {
	op, err := rp.federation.FetchEntityStatement(issuer)
	if err != nil {
		return nil, err
	}

	// TODO: check if entity is openid provider
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, fmt.Errorf("no openid provider metadata found")
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
		redirectUri: rp.entityStatement.Metadata.OpenidRelyingParty.RedirectURIs[0],
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
func loadKeys(privateKeyPath string, kid string, keyUsage jwk.KeyUsageType, certPath string) (jwk.Key, jwk.Key, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	privateKey, err := jwk.ParseKey(data, jwk.WithPEM(true))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse key file %s: %w", privateKeyPath, err)
	}

	privateKey.Set(jwk.KeyIDKey, kid)
	privateKey.Set(jwk.KeyUsageKey, keyUsage)

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key from private key: %w", err)
	}

	publicKey.Set(jwk.KeyIDKey, kid)
	publicKey.Set(jwk.KeyUsageKey, keyUsage)

	if keyUsage == jwk.ForEncryption {
		publicKey.Set(jwk.AlgorithmKey, jwa.ECDH_ES)
	} else {
		publicKey.Set(jwk.AlgorithmKey, jwa.ES256)
	}

	if certPath != "" {
		certDataDer, err := loadCertBytesFromPem(certPath)
		if err != nil {
			return nil, nil, err
		}
		var certChain cert.Chain
		certChain.AddString(base64.StdEncoding.EncodeToString(certDataDer))
		err = publicKey.Set(jwk.X509CertChainKey, &certChain)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to set cert chain: %w", err)
		}
	}

	return privateKey, publicKey, nil
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

func (rp *RelyingParty) Federation() *OpenidFederation {
	return rp.federation
}

func (rp *RelyingParty) ClientID() string {
	return rp.entityStatement.Subject
}
