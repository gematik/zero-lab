// Implementation of https://www.rfc-editor.org/rfc/rfc9449.html
package dpop

import (
	"crypto"
	"fmt"
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

type DPoP struct {
	JwtID           string
	HttpMethod      string
	HttpURI         string
	IssuedAt        time.Time
	AccessTokenHash string
	Nonce           string
	Key             jwk.Key
	KeyThumbprint   []byte
}

// Creates a new DPoP token ID.
func NewTokenId() string {
	return ksuid.New().String()
}

// Creates a new DPoP token with the given parameters.
func NewToken(
	tokenId string,
	httpMethod string,
	httpURI string,
	issuedAt time.Time,
	accessTokenHash string,
	nonce string,
) (jwt.Token, error) {
	token := jwt.New()

	// required
	if tokenId == "" {
		return nil, fmt.Errorf("tokenId is required")
	}
	token.Set("jti", tokenId)

	// required
	if httpMethod == "" {
		return nil, fmt.Errorf("httpMethod is required")
	}
	token.Set("htm", httpMethod)

	// required
	if httpURI == "" {
		return nil, fmt.Errorf("httpURI is required")
	}
	token.Set("htu", httpURI)

	// required
	if issuedAt.IsZero() {
		return nil, fmt.Errorf("issuedAt is required")
	}
	token.Set("iat", issuedAt.Unix())

	// optional
	if accessTokenHash != "" {
		token.Set("ath", accessTokenHash)
	}

	// optional
	if nonce != "" {
		token.Set("nonce", nonce)
	}

	return token, nil
}

// Signs a DPoP token with the given private key.
func SignToken(token jwt.Token, privateKey jwk.Key) ([]byte, error) {
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, err
	}

	headers := jws.NewHeaders()
	headers.Set("typ", "dpop+jwt")
	headers.Set("jwk", publicKey)

	return jwt.Sign(
		token,
		jwt.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(headers)),
	)
}

func ParseToken(tokenBytes []byte) (*DPoP, error) {
	// DANGER, parsing the token without verifying the signature
	unsafeMessage, err := jws.Parse(tokenBytes)
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

	verifiedToken, err := jwt.Parse(tokenBytes, jwt.WithKey(jwa.ES256, dpopKey))
	if err != nil {
		return nil, fmt.Errorf("unable to verify token: %w", err)
	}

	dpopToken := &DPoP{}

	dpopToken.JwtID, err = stringClaim(verifiedToken, "jti", true)
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
	dpopToken.KeyThumbprint, err = dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return dpopToken, nil
}

func stringClaim(token jwt.Token, name string, required bool) (string, error) {
	if claim, ok := token.Get(name); ok {
		if claimStr, ok := claim.(string); ok {
			return claimStr, nil
		}
		return "", fmt.Errorf("claim %s is not a string", name)
	}
	if required {
		return "", fmt.Errorf("claim %s is required", name)
	}
	return "", nil
}
