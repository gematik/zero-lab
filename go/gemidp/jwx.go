package gemidp

import (
	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// The gematik IDP signs its id_token with alg "BP256R1" (Brainpool). jwx must know this algorithm
// name to parse the token's JOSE header in parseIDToken — even though the signature is verified by
// josebp (stdlib ecdsa) and jwx only validates claims with jwt.WithVerify(false), so jwx never
// touches the Brainpool key or curve. Registering the name only (no signer/verifier) keeps jwx out
// of the Brainpool crypto.
func init() {
	jwa.RegisterSignatureAlgorithm(jwa.NewSignatureAlgorithm(josebp.AlgorithmNameBP256R1))
}
