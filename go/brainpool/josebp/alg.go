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

// Package josebp is a self-contained JOSE (JWS/JWT/JWK/JWE) implementation for the Brainpool
// elliptic curves used by the gematik telematik infrastructure (IDP-Dienst, SMC-B, ePA).
//
// It deliberately does NOT depend on github.com/lestrrat-go/jwx: the signing/verification crypto
// is done with stdlib crypto/ecdsa over the Brainpool curve (which jwx cannot do for x5c with a
// Brainpool cert, opaque smartcard signers, or ECDH-ES over Brainpool). It builds only on the
// low-level brainpool package (curves, PKI parsers, SignFunc).
package josebp

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/gematik/zero-lab/go/brainpool"
)

// JOSE signature algorithm names used in the gematik telematik infrastructure.
const (
	AlgorithmNameES256   = "ES256"
	algES384             = "ES384"
	algES512             = "ES512"
	AlgorithmNameBP256R1 = "BP256R1"
	algBP384R1           = "BP384R1"
	algBP512R1           = "BP512R1"
)

// hashForCurve returns the hash to use with ECDSA for the given curve's bit size.
func hashForCurve(curve elliptic.Curve) (hash.Hash, error) {
	switch curveBits := curve.Params().BitSize; curveBits {
	case 256:
		return sha256.New(), nil
	case 384:
		return sha512.New384(), nil
	case 512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported curve bit size: %d", curveBits)
	}
}

// bitSizeForAlg returns the curve bit size implied by a JOSE signature algorithm
// name as used in the gematik stack: ES256/BP256R1 → 256, ES384/BP384R1 → 384,
// ES512/BP512R1 → 512. It is the basis for the alg↔curve consistency check on
// verification (rejecting e.g. ES384 with a 256-bit key).
func bitSizeForAlg(alg string) (int, error) {
	switch alg {
	case AlgorithmNameES256, AlgorithmNameBP256R1:
		return 256, nil
	case algES384, algBP384R1:
		return 384, nil
	case algES512, algBP512R1:
		return 512, nil
	default:
		return 0, fmt.Errorf("unsupported signature algorithm: %s", alg)
	}
}

// jwaForCurve maps a Brainpool elliptic curve to its JOSE "crv" name.
func jwaForCurve(curve elliptic.Curve) string {
	switch curve.Params().Name {
	case "brainpoolP256r1":
		return "BP-256"
	case "brainpoolP384r1":
		return "BP-384"
	case "brainpoolP512r1":
		return "BP-512"
	default:
		return curve.Params().Name
	}
}

// curveForJWA maps a JOSE "crv" name to a Brainpool elliptic curve.
func curveForJWA(name string) (elliptic.Curve, error) {
	switch name {
	case "BP-256":
		return brainpool.P256r1(), nil
	case "BP-384":
		return brainpool.P384r1(), nil
	case "BP-512":
		return brainpool.P512r1(), nil
	default:
		return nil, fmt.Errorf("unsupported Brainpool curve: %s", name)
	}
}
