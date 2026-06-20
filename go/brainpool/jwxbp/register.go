// Package jwxbp plugs the Brainpool elliptic-curve signature algorithms (BP256R1, BP384R1,
// BP512R1, as used by the gematik IDP) into github.com/lestrrat-go/jwx/v3.
//
// Importing this package (its init registers everything) makes standard jwx work with
// Brainpool: jws.Sign/Verify, jwt.Sign/Parse, and jwk.ParseKey of EC keys on the brainpool
// curves. Import it for its side effects:
//
//	import _ "github.com/gematik/zero-lab/go/brainpool/jwxbp"
//
// then use the exported algorithm values, e.g. jwt.WithKey(jwxbp.BP256R1, key).
package jwxbp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwkecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Brainpool signature algorithms registered with jwx (use these with jws/jwt WithKey).
var (
	BP256R1 = jwa.NewSignatureAlgorithm(brainpool.AlgorithmNameBP256R1)
	BP384R1 = jwa.NewSignatureAlgorithm(brainpool.AlgorithmNameBP384R1)
	BP512R1 = jwa.NewSignatureAlgorithm(brainpool.AlgorithmNameBP512R1)
)

// Brainpool elliptic-curve names as used in JWK "crv" (per brainpool.JWAForCurve/CurveForJWA).
var (
	curveBP256 = jwa.NewEllipticCurveAlgorithm("BP-256")
	curveBP384 = jwa.NewEllipticCurveAlgorithm("BP-384")
	curveBP512 = jwa.NewEllipticCurveAlgorithm("BP-512")
)

type entry struct {
	sigAlg jwa.SignatureAlgorithm
	crvAlg jwa.EllipticCurveAlgorithm
	curve  elliptic.Curve
}

func init() {
	for _, e := range []entry{
		{BP256R1, curveBP256, brainpool.P256r1()},
		{BP384R1, curveBP384, brainpool.P384r1()},
		{BP512R1, curveBP512, brainpool.P512r1()},
	} {
		// Teach jwk's EC machinery about the brainpool curve (crv <-> elliptic.Curve).
		jwa.RegisterEllipticCurveAlgorithm(e.crvAlg)
		jwkecdsa.RegisterCurve(e.crvAlg, e.curve)

		// Register the signature algorithm + its signer/verifier (these also register the
		// algorithm name in jwx's database).
		jwa.RegisterSignatureAlgorithm(e.sigAlg)
		if err := jws.RegisterSigner(e.sigAlg, bpSigner{alg: e.sigAlg}); err != nil {
			panic(fmt.Sprintf("jwxbp: RegisterSigner(%s): %v", e.sigAlg, err))
		}
		if err := jws.RegisterVerifier(e.sigAlg, bpVerifier{}); err != nil {
			panic(fmt.Sprintf("jwxbp: RegisterVerifier(%s): %v", e.sigAlg, err))
		}
	}
}

// bpSigner implements jws.Signer2 for the Brainpool ECDSA algorithms, producing the raw
// fixed-width r‖s signature (RFC 7518 §3.4), reusing brainpool's signing primitive.
type bpSigner struct{ alg jwa.SignatureAlgorithm }

func (s bpSigner) Algorithm() jwa.SignatureAlgorithm { return s.alg }

func (s bpSigner) Sign(key any, payload []byte) ([]byte, error) {
	prk, err := ecdsaPrivateKey(key)
	if err != nil {
		return nil, err
	}
	h, err := brainpool.HashFunctionForCurve(prk.Curve)
	if err != nil {
		return nil, err
	}
	h.Write(payload)
	return brainpool.SignFuncPrivateKey(prk)(h.Sum(nil))
}

// bpVerifier implements jws.Verifier2 for the Brainpool ECDSA algorithms.
type bpVerifier struct{}

func (bpVerifier) Verify(key any, payload, signature []byte) error {
	puk, err := ecdsaPublicKey(key)
	if err != nil {
		return err
	}
	keyBytes := puk.Curve.Params().BitSize / 8
	if len(signature) != 2*keyBytes {
		return fmt.Errorf("jwxbp: invalid signature length %d (want %d)", len(signature), 2*keyBytes)
	}
	h, err := brainpool.HashFunctionForCurve(puk.Curve)
	if err != nil {
		return err
	}
	h.Write(payload)
	digest := h.Sum(nil)
	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])
	if !ecdsa.Verify(puk, digest, r, s) {
		return fmt.Errorf("jwxbp: signature verification failed")
	}
	return nil
}

func ecdsaPrivateKey(key any) (*ecdsa.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case ecdsa.PrivateKey:
		return &k, nil
	case jwk.Key:
		var raw ecdsa.PrivateKey
		if err := jwk.Export(k, &raw); err != nil {
			return nil, fmt.Errorf("jwxbp: export private key: %w", err)
		}
		return &raw, nil
	default:
		return nil, fmt.Errorf("jwxbp: unsupported private key type %T", key)
	}
}

func ecdsaPublicKey(key any) (*ecdsa.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return k, nil
	case ecdsa.PublicKey:
		return &k, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case jwk.Key:
		var raw ecdsa.PublicKey
		if err := jwk.Export(k, &raw); err != nil {
			return nil, fmt.Errorf("jwxbp: export public key: %w", err)
		}
		return &raw, nil
	default:
		return nil, fmt.Errorf("jwxbp: unsupported public key type %T", key)
	}
}
