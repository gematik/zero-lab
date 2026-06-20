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

type VerifierFunc func(token *JWT) error

type VerifierErrorUnsupportedSignatureAlgorithm error

func WithKey(key *JSONWebKey) VerifierFunc {
	return func(token *JWT) error {
		switch key.Key.(type) {
		case *ecdsa.PublicKey:
			return WithEcdsaPublicKey(key.Key.(*ecdsa.PublicKey))(token)
		default:
			return fmt.Errorf("unsupported key type")
		}
	}
}

func WithEcdsaPublicKey(pubKey *ecdsa.PublicKey) VerifierFunc {
	return func(token *JWT) error {
		alg, ok := token.Headers["alg"].(string)
		if !ok {
			return fmt.Errorf("missing alg header")
		}
		// TODO: check alg against the key's curve
		if alg != AlgorithmNameBP256R1 && alg != AlgorithmNameBP384R1 && alg != AlgorithmNameBP512R1 && alg != AlgorithmNameES256 && alg != AlgorithmNameES384 && alg != AlgorithmNameES512 {
			return VerifierErrorUnsupportedSignatureAlgorithm(fmt.Errorf("unsupported signature algorithm: %s", alg))
		}

		// Decode the signature into r‖s.
		curveBits := pubKey.Curve.Params().BitSize
		keyBytes := curveBits / 8

		rBytes := token.Signature[:keyBytes]
		sBytes := token.Signature[keyBytes:]

		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		// Hash the signing input (everything before the last '.').
		rawTokenNoSig := token.Raw[:bytes.LastIndex(token.Raw, []byte{'.'})]

		hashFunc, err := HashFunctionForCurve(pubKey.Curve)
		if err != nil {
			return err
		}

		hashFunc.Write(rawTokenNoSig)
		hash := hashFunc.Sum(nil)

		if !ecdsa.Verify(pubKey, hash, r, s) {
			return fmt.Errorf("signature verification failed")
		}

		return nil
	}
}

func ParseToken(rawToken []byte, verifiers ...VerifierFunc) (*JWT, error) {
	if len(rawToken) == 0 {
		return nil, fmt.Errorf("empty token")
	}
	if len(verifiers) == 0 {
		return nil, errors.New("at least one verifier must be specified")
	}
	parts := bytes.Split(rawToken, []byte{'.'})
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
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
