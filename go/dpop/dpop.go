// Implementation of https://www.rfc-editor.org/rfc/rfc9449.html
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
)

const (
	DPoPHeaderName = "DPoP"
	DPoPJwtType    = "dpop+jwt"
)

type PrivateKey struct {
	JwkPrivate jwk.Key
	JwkPublic  jwk.Key
	Thumbprint string
}

// Creates a new ephemeral private key for DPoP tokens.
func NewPrivateKey() (*PrivateKey, error) {
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}
	thumbprintBytes, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)

	publicKes, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create public key: %w", err)
	}

	return &PrivateKey{JwkPrivate: key, JwkPublic: publicKes, Thumbprint: thumbprint}, nil
}

type DPoP struct {
	Id              string
	HttpMethod      string
	HttpURI         string
	IssuedAt        time.Time
	AccessTokenHash string
	Nonce           string
	Key             jwk.Key
	KeyThumbprint   string
}

type Builder struct {
	dpop *DPoP
}

func NewBuilder() *Builder {
	return &Builder{dpop: &DPoP{}}
}

func (b *Builder) Build() (*DPoP, error) {
	// set defaults if possible and necessary
	if b.dpop.Id == "" {
		b.dpop.Id = ksuid.New().String()
	}
	if b.dpop.IssuedAt.IsZero() {
		b.dpop.IssuedAt = time.Now()
	}

	if err := b.dpop.validate(); err != nil {
		return nil, err
	}
	return b.dpop, nil
}

func (b *Builder) Id(id string) *Builder {
	b.dpop.Id = id
	return b
}

func (b *Builder) HttpMethod(httpMethod string) *Builder {
	b.dpop.HttpMethod = httpMethod
	return b
}

func (b *Builder) HttpURI(httpURI string) *Builder {
	b.dpop.HttpURI = httpURI
	return b
}

func (b *Builder) HttpRequest(request *http.Request) *Builder {
	b.dpop.HttpMethod = request.Method
	b.dpop.HttpURI = request.URL.String()
	return b
}

func (b *Builder) AccessTokenHash(accessTokenHash string) *Builder {
	b.dpop.AccessTokenHash = accessTokenHash
	return b
}

func (b *Builder) Nonce(nonce string) *Builder {
	b.dpop.Nonce = nonce
	return b
}

func (dpop *DPoP) validate() error {
	if dpop.Id == "" {
		return fmt.Errorf("JWT ID (jti) is required")
	}
	if dpop.HttpMethod == "" {
		return fmt.Errorf("HTTP Method (htm) is required")
	}
	if dpop.HttpURI == "" {
		return fmt.Errorf("HTTP URI (htu) is required")
	}
	if dpop.IssuedAt.IsZero() {
		return fmt.Errorf("DPoP issued at timestamp (iat) is required")
	}
	return nil
}

// Signs the DPoP token with the given private key and returns
// the compact serialized token.
func (dpop *DPoP) Sign(privateKey *PrivateKey) (string, error) {
	if err := dpop.validate(); err != nil {
		return "", err
	}
	token := jwt.New()

	token.Set("jti", dpop.Id)
	token.Set("htm", dpop.HttpMethod)
	token.Set("htu", dpop.HttpURI)
	token.Set("iat", dpop.IssuedAt.Unix())

	if dpop.AccessTokenHash != "" {
		token.Set("ath", dpop.AccessTokenHash)
	}

	if dpop.Nonce != "" {
		token.Set("nonce", dpop.Nonce)
	}

	headers := jws.NewHeaders()
	headers.Set("typ", "dpop+jwt")
	headers.Set("jwk", privateKey.JwkPublic)

	bytes, err := jwt.Sign(
		token,
		jwt.WithKey(jwa.ES256, privateKey.JwkPrivate, jws.WithProtectedHeaders(headers)),
	)
	if err != nil {
		return "", fmt.Errorf("unable to sign token: %w", err)
	}
	return string(bytes), nil
}

type ParseOptions struct {
	MaxAge        time.Duration
	NonceRequired bool
}

func ParseRequest(request *http.Request, options ParseOptions) (*DPoP, *DPoPError) {
	dpopHeader := request.Header.Get(DPoPHeaderName)
	if dpopHeader == "" {
		return nil, &ErrMissingHeader
	}

	token, err := Parse(dpopHeader)
	if err != nil {
		return nil, &DPoPError{HttpStatus: http.StatusBadRequest, Code: "invalid_dpop_proof", Description: err.Error()}
	}

	// Check the issued at time
	if options.MaxAge > 0 && time.Since(token.IssuedAt) > options.MaxAge {
		return nil, &DPoPError{HttpStatus: http.StatusBadRequest, Code: "invalid_dpop_proof", Description: "DPoP is too old"}
	}

	// Check if nonce is required
	if options.NonceRequired && token.Nonce == "" {
		return nil, &ErrUseDPoPNonce
	}

	return token, nil
}

func Parse(token string) (*DPoP, error) {
	// DANGER, parsing the token without verifying the signature
	unsafeMessage, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("unable to parse token: %w", err)
	}

	if unsafeMessage.Signatures() == nil || len(unsafeMessage.Signatures()) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	signature := unsafeMessage.Signatures()[0]
	if signature.ProtectedHeaders() == nil {
		return nil, fmt.Errorf("no protected headers found")
	}

	protectedHeaders := signature.ProtectedHeaders()

	if protectedHeaders.Type() != DPoPJwtType {
		return nil, fmt.Errorf("invalid token type: %s", protectedHeaders.Type())
	}

	if protectedHeaders.JWK() == nil {
		return nil, fmt.Errorf("JWK is not found or invalid")
	}

	dpopKey := signature.ProtectedHeaders().JWK()

	// parse and verify now using the key
	verifiedToken, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.ES256, dpopKey))
	if err != nil {
		return nil, fmt.Errorf("unable to verify token: %w", err)
	}

	dpopToken := &DPoP{}

	dpopToken.Id, err = stringClaim(verifiedToken, "jti", true)
	if err != nil {
		return nil, err
	}

	dpopToken.HttpMethod, err = stringClaim(verifiedToken, "htm", true)
	if err != nil {
		return nil, err
	}

	dpopToken.HttpURI, err = stringClaim(verifiedToken, "htu", true)
	if err != nil {
		return nil, err
	}

	dpopToken.IssuedAt = verifiedToken.IssuedAt()
	if dpopToken.IssuedAt.IsZero() {
		return nil, fmt.Errorf("claim iat is required")
	}

	dpopToken.AccessTokenHash, err = stringClaim(verifiedToken, "ath", false)
	if err != nil {
		return nil, err
	}

	dpopToken.Nonce, err = stringClaim(verifiedToken, "nonce", false)
	if err != nil {
		return nil, err
	}

	dpopToken.Key = dpopKey
	thumbprintBytes, err := dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	dpopToken.KeyThumbprint = base64.RawURLEncoding.EncodeToString(thumbprintBytes)

	return dpopToken, nil
}

func stringClaim(token jwt.Token, name string, required bool) (string, error) {
	if claim, ok := token.Get(name); ok {
		if claimStr, ok := claim.(string); ok {
			return claimStr, nil
		}
		return "", fmt.Errorf("claim '%s' is not a string", name)
	}
	if required {
		return "", fmt.Errorf("claim '%s' is required", name)
	}
	return "", nil
}
