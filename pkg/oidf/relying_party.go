package oidf

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"gopkg.in/yaml.v3"
)

type RelyingPartyConfig struct {
	Url                  string                 `yaml:"url" validate:"required"`
	FedMasterURL         string                 `yaml:"fed_master_url" validate:"required"`
	FedMasterJwks        map[string]interface{} `yaml:"fed_master_jwks" validate:"required"`
	SignKid              string                 `yaml:"sign_kid" validate:"required"`
	SignPrivateKeyPath   string                 `yaml:"sign_private_key_path" validate:"required"`
	EncKid               string                 `yaml:"enc_kid" validate:"required"`
	EncPrivateKeyPath    string                 `yaml:"enc_private_key_path" validate:"required"`
	ClientKid            string                 `yaml:"client_kid" validate:"required"`
	ClientPrivateKeyPath string                 `yaml:"client_private_key_path" validate:"required"`
	ClientCertPath       string                 `yaml:"client_cert_path" validate:"required"`
	MetadataTemplate     map[string]interface{} `yaml:"metadata" validate:"required"`
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
	var cfg RelyingPartyConfig
	err = yaml.Unmarshal(yamlData, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file '%s': %w", path, err)
	}
	return &cfg, nil
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

	err := validate.Struct(cfg)
	if err != nil {
		return nil, err
	}

	trustAnchor, err := mapToJwks(cfg.FedMasterJwks)
	if err != nil {
		return nil, err
	}

	rp := RelyingParty{
		cfg:         cfg,
		trustAnchor: trustAnchor,
	}

	var sigPublicKey jwk.Key
	rp.sigPrivateKey, sigPublicKey, err = loadKeys(cfg.SignPrivateKeyPath, cfg.SignKid, jwk.ForSignature, "")
	if err != nil {
		return nil, err
	}

	var encPublicKey jwk.Key
	rp.encPrivateKey, encPublicKey, err = loadKeys(cfg.EncPrivateKeyPath, cfg.EncKid, jwk.ForEncryption, "")
	if err != nil {
		return nil, err
	}

	var clientPublicKey jwk.Key
	rp.clientPrivateKey, clientPublicKey, err = loadKeys(cfg.ClientPrivateKeyPath, cfg.ClientKid, jwk.ForSignature, cfg.ClientCertPath)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientPrivateKeyPath)
	rp.httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: util.AddApiKeyTransport(
			&http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
				},
			},
		),
	}

	metadata, err := templateToMetadata(cfg.MetadataTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to convert metadata template: %w", err)
	}

	if metadata.OpenidRelyingParty == nil {
		return nil, fmt.Errorf("template must contain openid_relying_party")
	}

	rp.entityStatement = &EntityStatement{
		Issuer:   cfg.Url,
		Subject:  cfg.Url,
		Metadata: metadata,
	}

	rp.entityStatement.Jwks = &util.Jwks{Keys: jwk.NewSet()}
	rp.entityStatement.Jwks.Keys.AddKey(sigPublicKey)

	entityJwks := jwk.NewSet()
	entityJwks.AddKey(encPublicKey)
	entityJwks.AddKey(clientPublicKey)

	rp.entityStatement.Metadata.OpenidRelyingParty.Jwks = &util.Jwks{Keys: entityJwks}

	rp.federation, err = NewOpenidFederation(cfg.FedMasterURL, rp.trustAnchor)
	if err != nil {
		return nil, err
	}

	return &rp, nil
}

func (rp *RelyingParty) Sign() ([]byte, error) {

	token, err := jwt.NewBuilder().
		Issuer(rp.cfg.Url).
		Subject(rp.cfg.Url).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour*24)).
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
			jwa.ES256,
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
	signed, err := rp.Sign()
	if err != nil {
		slog.Error("unable to sign entity statement", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	w.Write(signed)
}

type pushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (rp *RelyingParty) NewClient(iss string) (*RelyingPartyClient, error) {
	op, err := rp.federation.FetchEntityStatement(iss)
	if err != nil {
		return nil, err
	}

	return &RelyingPartyClient{
		rp:          rp,
		op:          op,
		scopes:      []string{"urn:telematik:display_name", "urn:telematik:versicherter", "openid"},
		redirectURI: rp.entityStatement.Metadata.OpenidRelyingParty.RedirectURIs[0],
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

func (rp *RelyingParty) Federation() *OpenidFederation {
	return rp.federation
}

// converts a map containing jwks to jwks object
func mapToJwks(m map[string]interface{}) (jwk.Set, error) {
	// convert map to json first
	jsonData, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	// convert json to jwks
	jwks, err := jwk.Parse(jsonData)
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func (rp *RelyingParty) ClientID() string {
	return rp.cfg.Url
}
