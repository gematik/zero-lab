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

package josebp

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// VerifierFunc checks the signature of a parsed token; ParseToken fails if any
// of its verifiers returns an error.
type VerifierFunc func(token *JWT) error

// WithKey verifies the token's ECDSA signature with the public key of key. The
// alg header must match the key's curve.
func WithKey(key *JSONWebKey) VerifierFunc {
	return func(token *JWT) error {
		switch pub := key.Key.(type) {
		case *ecdsa.PublicKey:
			return withECDSAPublicKey(pub)(token)
		default:
			return errors.New("unsupported key type")
		}
	}
}

func withECDSAPublicKey(pubKey *ecdsa.PublicKey) VerifierFunc {
	return func(token *JWT) error {
		alg, ok := token.Headers["alg"].(string)
		if !ok {
			return errors.New("missing alg header")
		}
		algBits, err := bitSizeForAlg(alg)
		if err != nil {
			return err
		}
		// Reject a token whose algorithm does not match the verifying key's
		// curve (e.g. ES384 against a brainpoolP256r1 key). Without this an
		// attacker can choose any alg the key happens to support.
		if algBits != pubKey.Curve.Params().BitSize {
			return fmt.Errorf("algorithm %s does not match key curve %s", alg, pubKey.Curve.Params().Name)
		}

		// Decode the signature into r‖s.
		curveBits := pubKey.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if len(token.Signature) != 2*keyBytes {
			return fmt.Errorf("signature is %d bytes, want %d for %s", len(token.Signature), 2*keyBytes, alg)
		}

		rBytes := token.Signature[:keyBytes]
		sBytes := token.Signature[keyBytes:]

		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		// Hash the signing input (everything before the last '.').
		rawTokenNoSig := token.Raw[:bytes.LastIndex(token.Raw, []byte{'.'})]

		hashFunc, err := hashForCurve(pubKey.Curve)
		if err != nil {
			return err
		}

		hashFunc.Write(rawTokenNoSig)
		hash := hashFunc.Sum(nil)

		if !ecdsa.Verify(pubKey, hash, r, s) {
			return errors.New("signature verification failed")
		}

		return nil
	}
}

// ParseToken decodes a compact JWS and runs every verifier on it; at least one
// verifier is required, so an unverified token is never returned.
func ParseToken(rawToken []byte, verifiers ...VerifierFunc) (*JWT, error) {
	if len(rawToken) == 0 {
		return nil, errors.New("empty token")
	}
	if len(verifiers) == 0 {
		return nil, errors.New("at least one verifier must be specified")
	}
	parts := bytes.Split(rawToken, []byte{'.'})
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	token := &JWT{
		Raw: rawToken,
	}

	var err error

	if token.HeadersJson, err = base64.RawURLEncoding.DecodeString(string(parts[0])); err != nil {
		return nil, fmt.Errorf("decoding headers: %w", err)
	}

	if err = json.Unmarshal(token.HeadersJson, &token.Headers); err != nil {
		return nil, fmt.Errorf("unmarshaling headers: %w", err)
	}

	if token.PayloadJson, err = base64.RawURLEncoding.DecodeString(string(parts[1])); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}

	if err = json.Unmarshal(token.PayloadJson, &token.Claims); err != nil {
		return nil, fmt.Errorf("unmarshaling claims: %w", err)
	}

	if token.Signature, err = base64.RawURLEncoding.DecodeString(string(parts[2])); err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	for _, verifier := range verifiers {
		if err := verifier(token); err != nil {
			return nil, fmt.Errorf("verifying token: %w", err)
		}
	}

	return token, nil
}
