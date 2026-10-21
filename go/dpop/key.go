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

package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"
)

// Key is a client's DPoP key (Section 2): the private key as a [crypto.Signer], so it may stay
// in hardware and is only ever used to sign, and the public key every proof carries.
type Key struct {
	signer     crypto.Signer
	alg        jose.SignatureAlgorithm
	public     jose.JSONWebKey
	thumbprint string
}

// NewKey generates an ephemeral P-256 key, signing ES256.
func NewKey() (*Key, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("dpop: generate key: %w", err)
	}
	return NewKeyFromSigner(private)
}

// NewKeyFromSigner makes signer a DPoP key. ECDSA keys on P-256, P-384 and P-521 sign ES256,
// ES384 and ES512, Ed25519 keys sign EdDSA: all asymmetric, as Section 4.2 requires. Other
// keys are refused.
func NewKeyFromSigner(signer crypto.Signer) (*Key, error) {
	alg, err := algorithmOf(signer.Public())
	if err != nil {
		return nil, err
	}
	public := jose.JSONWebKey{Key: signer.Public()}
	thumbprint, err := thumbprintOf(public)
	if err != nil {
		return nil, err
	}
	return &Key{signer: signer, alg: alg, public: public, thumbprint: thumbprint}, nil
}

func algorithmOf(public crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch k := public.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", fmt.Errorf("dpop: unsupported curve %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	}
	return "", fmt.Errorf("dpop: unsupported key type %T", public)
}

// Thumbprint is the base64url-encoded SHA-256 JWK thumbprint (RFC 7638) of the key: the
// jkt an authorization server binds the access token to (Section 6.1) and the dpop_jkt of
// an authorization request (Section 10).
func (k *Key) Thumbprint() string { return k.thumbprint }

// Algorithm is the JWS algorithm the key signs proofs with.
func (k *Key) Algorithm() string { return string(k.alg) }

// Public is the key's public JWK, as each proof's jwk header carries it.
func (k *Key) Public() jose.JSONWebKey { return k.public }

// thumbprintOf is jwk's JWK SHA-256 thumbprint (RFC 7638), base64url-encoded without
// padding (Section 6.1).
func thumbprintOf(jwk jose.JSONWebKey) (string, error) {
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// opaqueSigner lets go-jose sign with the [crypto.Signer] without seeing the private key.
type opaqueSigner struct{ key *Key }

func (s opaqueSigner) Public() *jose.JSONWebKey { return &s.key.public }

func (s opaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{s.key.alg}
}

// SignPayload signs the JWS signing input: Ed25519 over the input itself, ECDSA over its
// digest, the signature converted from the signer's ASN.1 DER to JWS's fixed-length R‖S
// (RFC 7518 Section 3.4).
func (s opaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != s.key.alg {
		return nil, fmt.Errorf("dpop: key signs %s, not %s", s.key.alg, alg)
	}
	if alg == jose.EdDSA {
		return s.key.signer.Sign(rand.Reader, payload, crypto.Hash(0))
	}
	hash, size := crypto.SHA256, 32
	switch alg {
	case jose.ES384:
		hash, size = crypto.SHA384, 48
	case jose.ES512:
		hash, size = crypto.SHA512, 66
	}
	h := hash.New()
	h.Write(payload)
	der, err := s.key.signer.Sign(rand.Reader, h.Sum(nil), hash)
	if err != nil {
		return nil, fmt.Errorf("dpop: sign: %w", err)
	}
	return rawECDSA(der, size)
}

// rawECDSA converts an ASN.1 DER ECDSA signature to R‖S, each left-padded to size bytes.
func rawECDSA(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("dpop: signer returned a malformed ECDSA signature")
	}
	if sig.R.BitLen() > 8*size || sig.S.BitLen() > 8*size {
		return nil, errors.New("dpop: signer returned an ECDSA signature too long for its curve")
	}
	raw := make([]byte, 2*size)
	sig.R.FillBytes(raw[:size])
	sig.S.FillBytes(raw[size:])
	return raw, nil
}
