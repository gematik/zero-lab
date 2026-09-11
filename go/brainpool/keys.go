package brainpool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// ParsePrivateKeyPEM parses a PKCS#8 ("PRIVATE KEY") or SEC 1 ("EC PRIVATE
// KEY") PEM block holding an ECDSA key.
func ParsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("brainpool: no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("brainpool: PKCS#8 block holds a %T, not an ECDSA key", key)
		}
		return ecdsaKey, nil
	case "EC PRIVATE KEY":
		return ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("brainpool: unsupported PEM block type %q", block.Type)
}

// ecPrivateKey is the SEC 1 / RFC 5915 ECPrivateKey structure.
type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	NamedCurve asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseECPrivateKey parses a SEC 1 EC private key; keys on other curves are
// handed to x509.ParseECPrivateKey.
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var key ecPrivateKey
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("brainpool: parse EC private key: %w", err)
	}
	if key.Version != 1 {
		return nil, fmt.Errorf("brainpool: unknown EC private key version %d", key.Version)
	}
	curve, ok := curveFromOID(key.NamedCurve)
	if !ok {
		return x509.ParseECPrivateKey(der)
	}
	return privateKeyFromScalar(curve, key.PrivateKey)
}

// ParsePKCS8PrivateKey parses a PKCS#8 private key; anything but an EC key on
// a Brainpool curve is handed to x509.ParsePKCS8PrivateKey.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	var info struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("brainpool: parse PKCS#8 private key: %w", err)
	}
	if !info.Algorithm.Algorithm.Equal(oidECPublicKey) {
		return x509.ParsePKCS8PrivateKey(der)
	}
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, fmt.Errorf("brainpool: parse PKCS#8 curve OID: %w", err)
	}
	curve, ok := curveFromOID(curveOID)
	if !ok {
		return x509.ParsePKCS8PrivateKey(der)
	}
	var key ecPrivateKey
	if _, err := asn1.Unmarshal(info.PrivateKey, &key); err != nil {
		return nil, fmt.Errorf("brainpool: parse PKCS#8 EC private key: %w", err)
	}
	return privateKeyFromScalar(curve, key.PrivateKey)
}

// privateKeyFromScalar builds the key from its scalar. The public point is
// recomputed rather than trusted from the file, as the standard library does;
// for brainpoolP256r1 that multiplication touches the secret and runs in the
// constant-time core.
func privateKeyFromScalar(curve elliptic.Curve, scalar []byte) (*ecdsa.PrivateKey, error) {
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() == 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("brainpool: private scalar out of range [1, n-1]")
	}
	x, y, err := derivePublicKey(curve, d)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}
