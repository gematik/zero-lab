package authzserver

import (
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

type VerifyClientAssertionFunc func(assertion string) (*ClientAssertionClaims, error)

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
	ClientSelfAssessment ClientSelfAssessment `json:"urn:telematik:client-self-assessment" validate:"required"`
}

type ClientSelfAssessment struct {
	ProductID      string `json:"product_id" validate:"required"`
	ProductVersion string `json:"product_version" validate:"required"`
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
	err := validate.Struct(c)
	return err
}
