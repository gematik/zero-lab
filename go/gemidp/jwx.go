// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
