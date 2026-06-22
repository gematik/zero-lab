package authzserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type for private_key_jwt (RFC 7523 §2.2).
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAssertionClaims are the claims of a private_key_jwt client assertion. Beyond the standard
// RFC 7523 claims it keeps the gematik extensions: a nonce (redeemed against the AS nonce service)
// and cnf.jkt (the client's DPoP key, to which the issued access token is sender-constrained).
type ClientAssertionClaims struct {
	Nonce string   `json:"nonce" validate:"required"`
	Iss   string   `json:"iss" validate:"required"`
	Sub   string   `json:"sub" validate:"required"`
	Aud   []string `json:"aud" validate:"required"`
	Iat   int      `json:"iat" validate:"required"`
	Exp   int      `json:"exp" validate:"required"`
	Cnf   struct {
		Jkt string `json:"jkt" validate:"required"`
	} `json:"cnf" validate:"required"`
}

func (c *ClientAssertionClaims) Validate() error {
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name, _, _ := strings.Cut(fld.Tag.Get("json"), ",")
		if name == "-" {
			return ""
		}
		return name
	})
	return validate.Struct(c)
}

// parseClientAssertionClaims decodes the claims of a compact JWT without verifying its signature.
func parseClientAssertionClaims(assertion string) (*ClientAssertionClaims, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed client_assertion")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode client_assertion payload: %w", err)
	}
	claims := new(ClientAssertionClaims)
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, fmt.Errorf("unmarshal client_assertion claims: %w", err)
	}
	return claims, nil
}
