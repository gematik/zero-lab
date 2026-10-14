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
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/gematik/zero-lab/go/brainpool"
)

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
func (jwk *JSONWebKey) UnmarshalJSON(data []byte) error {
	type Alias JSONWebKey
	var jwkAlias Alias
	if err := json.Unmarshal(data, &jwkAlias); err != nil {
		return err
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
				PublicKey: ecdsa.PublicKey{
					Curve: curve,
					X:     x,
					Y:     y,
				},
				D: d,
			}
		} else {
			jwkAlias.Key = &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}
		}

	default:
		return fmt.Errorf("unsupported key type: %s", jwkAlias.KeyType)
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
		jwkAlias.D = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
		jwkAlias.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwkAlias.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	} else if key, ok := jwk.Key.(*ecdsa.PublicKey); ok {
		jwkAlias.KeyType = "EC"
		jwkAlias.CurveName = jwaForCurve(key.Curve)
		jwkAlias.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwkAlias.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	}

	if len(jwk.Certificates) > 0 {
		jwkAlias.CertificatesRaw = make([][]byte, len(jwk.Certificates))
		for i, cert := range jwk.Certificates {
			jwkAlias.CertificatesRaw[i] = cert.Raw
		}
	}

	return json.Marshal(jwkAlias)
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
