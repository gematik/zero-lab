package josebp

import (
	"crypto/ecdsa"
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
	Algortihm       string              `json:"alg,omitempty"`
	KeyID           string              `json:"kid,omitempty"`
	Key             any                 `json:"-"`
	CertificatesRaw [][]byte            `json:"x5c,omitempty"`
	Certificates    []*x509.Certificate `json:"-"`
	X               string              `json:"x"`
	Y               string              `json:"y"`
	D               string              `json:"d,omitempty"`
	CurveName       string              `json:"crv"`
}

func (jwk *JSONWebKey) UnmarshalJSON(data []byte) error {
	type Alias JSONWebKey
	var jwkAlias Alias
	if err := json.Unmarshal(data, &jwkAlias); err != nil {
		return err
	}

	switch jwkAlias.KeyType {
	case "EC":
		curve, err := CurveForJWA(jwkAlias.CurveName)
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

		if jwkAlias.D != "" {
			d, err := parseBigInt(jwkAlias.D)
			if err != nil {
				return fmt.Errorf("failed to parse d: %w", err)
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

func (jwk *JSONWebKey) MarshalJSON() ([]byte, error) {
	type Alias JSONWebKey
	var jwkAlias Alias = Alias(*jwk)

	if key, ok := jwk.Key.(*ecdsa.PrivateKey); ok {
		jwkAlias.D = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
		jwkAlias.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwkAlias.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	} else if key, ok := jwk.Key.(*ecdsa.PublicKey); ok {
		jwkAlias.KeyType = "EC"
		jwkAlias.CurveName = JWAForCurve(key.Curve)
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

func parseBigInt(s string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return new(big.Int).SetBytes(bytes), nil
}
