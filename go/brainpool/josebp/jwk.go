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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"

	"github.com/gematik/zero-lab/go/brainpool"
)

// decodeError is a JSON text from outside that did not decode. Its text names what was decoded, never the input: the
// decoder's own message quotes member names and values (servers.md rule 14). The decoder's error stays reachable
// through errors.Is and errors.As, so a caller can still tell a member named twice from a mismatched type.
type decodeError struct {
	what string
	err  error
}

func (e *decodeError) Error() string { return e.what + ": does not decode" }

func (e *decodeError) Unwrap() error { return e.err }

// JSONWebKey is a Brainpool-aware JWK (RFC 7517) — it understands the "BP-256/384/512" crv names
// and parses x5c Brainpool certificates via brainpool.ParseCertificate (crypto/x509 cannot).
type JSONWebKey struct {
	KeyType         string              `json:"kty"`
	Use             string              `json:"use,omitempty"`
	Algorithm       string              `json:"alg,omitempty"`
	KeyID           string              `json:"kid,omitempty"`
	Key             any                 `json:"-"`
	CertificatesRaw [][]byte            `json:"x5c,omitempty"`
	Certificates    []*x509.Certificate `json:"-"`
	X               string              `json:"x"`
	Y               string              `json:"y"`
	D               string              `json:"d,omitempty"`
	CurveName       string              `json:"crv"`
}

// UnmarshalJSON decodes an EC JWK with a NIST or Brainpool crv, validates the
// public point and parses the x5c certificates with brainpool.ParseCertificate.
//
// Its own errors quote nothing of the key. Through json.Unmarshal, though, the
// outer decoder checks the whole text first, and its error for a member named
// twice or a syntax error quotes the input: a caller decoding a key from
// outside wraps that error in a reason of its own (servers.md rule 14).
func (jwk *JSONWebKey) UnmarshalJSON(data []byte) error {
	type Alias JSONWebKey
	var jwkAlias Alias
	if err := json.Unmarshal(data, &jwkAlias); err != nil {
		return &decodeError{what: "JWK", err: err}
	}

	switch jwkAlias.KeyType {
	case "EC":
		curve, err := curveForJWA(jwkAlias.CurveName)
		if err != nil {
			return err
		}

		x, err := parseBigInt(jwkAlias.X)
		if err != nil {
			return fmt.Errorf("failed to parse x: %w", err)
		}

		y, err := parseBigInt(jwkAlias.Y)
		if err != nil {
			return fmt.Errorf("failed to parse y: %w", err)
		}

		// Reject points that are off-curve or out of range before constructing a
		// key. Without this an attacker-supplied JWK can mount an invalid-curve
		// attack against later ECDH/verify operations.
		if err := brainpool.ValidatePublicKey(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}); err != nil {
			return err
		}

		if jwkAlias.D != "" {
			d, err := parseBigInt(jwkAlias.D)
			if err != nil {
				return fmt.Errorf("failed to parse d: %w", err)
			}

			if err := validateECPrivateScalar(curve, d); err != nil {
				return err
			}

			jwkAlias.Key = &ecdsa.PrivateKey{
				Curve: curve,
				X:     x,
				Y:     y,
				D:     d,
			}
		} else {
			jwkAlias.Key = &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}
		}

	default:
		return errors.New("unsupported key type")
	}

	if len(jwkAlias.CertificatesRaw) > 0 {
		jwkAlias.Certificates = make([]*x509.Certificate, len(jwkAlias.CertificatesRaw))
		for i, certRaw := range jwkAlias.CertificatesRaw {
			cert, err := brainpool.ParseCertificate(certRaw)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			jwkAlias.Certificates[i] = cert
		}
	}

	*jwk = JSONWebKey(jwkAlias)
	return nil
}

// MarshalJSON encodes the key, including d for a private key, with the
// Brainpool crv names and the certificates as x5c.
func (jwk *JSONWebKey) MarshalJSON() ([]byte, error) {
	type Alias JSONWebKey
	jwkAlias := Alias(*jwk)

	if key, ok := jwk.Key.(*ecdsa.PrivateKey); ok {
		jwkAlias.D = encodeCoordinate(key.D, key.Curve)
		jwkAlias.X = encodeCoordinate(key.X, key.Curve)
		jwkAlias.Y = encodeCoordinate(key.Y, key.Curve)
	} else if key, ok := jwk.Key.(*ecdsa.PublicKey); ok {
		jwkAlias.KeyType = "EC"
		jwkAlias.CurveName = jwaForCurve(key.Curve)
		jwkAlias.X = encodeCoordinate(key.X, key.Curve)
		jwkAlias.Y = encodeCoordinate(key.Y, key.Curve)
	}

	if len(jwk.Certificates) > 0 {
		jwkAlias.CertificatesRaw = make([][]byte, len(jwk.Certificates))
		for i, cert := range jwk.Certificates {
			jwkAlias.CertificatesRaw[i] = cert.Raw
		}
	}

	return json.Marshal(jwkAlias)
}

// encodeCoordinate writes value at the curve's full length, as RFC 7518 6.2.1.2 and 6.2.2.1 require: big.Int
// alone drops leading zeros, and a strict peer refuses the short form.
func encodeCoordinate(value *big.Int, curve elliptic.Curve) string {
	return base64.RawURLEncoding.EncodeToString(value.FillBytes(make([]byte, (curve.Params().BitSize+7)/8)))
}

// validateECPrivateScalar checks d ∈ [1, n-1].
func validateECPrivateScalar(curve elliptic.Curve, d *big.Int) error {
	n := curve.Params().N
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		return fmt.Errorf("private scalar out of range [1, n-1] for %s", curve.Params().Name)
	}
	return nil
}

func parseBigInt(s string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return new(big.Int).SetBytes(bytes), nil
}
