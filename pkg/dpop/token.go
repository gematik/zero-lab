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
func NewTokenID() string {
	return ksuid.New().String()
}

// Signs the DPoP token with the given private key and returns
// the compact serialized token.
func (dpop *DPoP) Sign(privateKey jwk.Key) ([]byte, error) {
	token := jwt.New()

	if dpop.JwtID == "" {
		dpop.JwtID = NewTokenID()
	}
	token.Set("jti", dpop.JwtID)

	if dpop.HttpMethod == "" {
		return nil, fmt.Errorf("httpMethod is required")
	}
	token.Set("htm", dpop.HttpMethod)

	if dpop.HttpURI == "" {
		return nil, fmt.Errorf("httpURI is required")
	}
	token.Set("htu", dpop.HttpURI)

	if dpop.IssuedAt.IsZero() {
		return nil, fmt.Errorf("issuedAt is required")
	}

	token.Set("iat", dpop.IssuedAt.Unix())

	if dpop.AccessTokenHash != "" {
		token.Set("ath", dpop.AccessTokenHash)
	}

	if dpop.Nonce != "" {
		token.Set("nonce", dpop.Nonce)
	}

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

func Parse(tokenBytes []byte) (*DPoP, error) {
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
		return "", fmt.Errorf("claim '%s' is not a string", name)
	}
	if required {
		return "", fmt.Errorf("claim '%s' is required", name)
	}
	return "", nil
}
