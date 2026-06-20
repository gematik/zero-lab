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
	AlgorithmNameES384   = "ES384"
	AlgorithmNameES512   = "ES512"
	AlgorithmNameBP256R1 = "BP256R1"
	AlgorithmNameBP384R1 = "BP384R1"
	AlgorithmNameBP512R1 = "BP512R1"
)

// HashFunctionForCurve returns the hash to use with ECDSA for the given curve's bit size.
func HashFunctionForCurve(curve elliptic.Curve) (hash.Hash, error) {
	curveBits := curve.Params().BitSize

	var hashFunc hash.Hash
	if curveBits == 256 {
		hashFunc = sha256.New()
	} else if curveBits == 384 {
		hashFunc = sha512.New384()
	} else if curveBits == 512 {
		hashFunc = sha512.New()
	} else {
		return nil, fmt.Errorf("unsupported curve bit size: %d", curveBits)
	}

	return hashFunc, nil
}

// AlgorithmForCurve maps an elliptic curve to its JOSE signature algorithm name.
func AlgorithmForCurve(curve elliptic.Curve) (string, error) {
	name := curve.Params().Name

	switch name {
	case "P-256":
		return AlgorithmNameES256, nil
	case "P-384":
		return AlgorithmNameBP384R1, nil
	case "P-521":
		return AlgorithmNameES512, nil
	case "BP-256":
		return AlgorithmNameBP256R1, nil
	case "BP-384":
		return AlgorithmNameBP384R1, nil
	case "BP-521":
		return AlgorithmNameBP512R1, nil
	default:
		return "", fmt.Errorf("unsupported curve: %s", name)
	}
}

// JWAForCurve maps a Go elliptic curve to its JOSE "crv" name (Brainpool included).
func JWAForCurve(curve elliptic.Curve) string {
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

// CurveForJWA maps a JOSE "crv" name to a Go elliptic curve (Brainpool included).
func CurveForJWA(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	case "BP-256":
		return brainpool.P256r1(), nil
	case "BP-384":
		return brainpool.P384r1(), nil
	case "BP-512":
		return brainpool.P512r1(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}
