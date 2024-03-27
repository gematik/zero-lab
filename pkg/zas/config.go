// configuration of a Zero Trust Authorization Server (ZAS)
package zas

import (
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Config struct {
	OIDCConfigs            []*oidc.Config
	OIDFRelyingPartyConfig *oidf.RelyingPartyConfig
	SigningKey             jwk.Key
	EncryptionKey          jwk.Key
}
