package oauth2server

import (
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Config struct {
	Issuer                 string `json:"issuer"`
	OIDCConfigs            []*oidc.Config
	OIDFRelyingPartyConfig *oidf.RelyingPartyConfig
	SigningKey             jwk.Key
	EncryptionKey          jwk.Key
}
