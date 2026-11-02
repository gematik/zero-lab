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

package authzserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// es256SignatureOctets is the size of R and of S in a JWS ES256 signature (RFC 7518 Section 3.4).
const es256SignatureOctets = 32

// SigningKey is what the server signs its tokens with. It holds a function, not key material
// (docs/design/keys.md, rule 1), so a command can hand in a key in an HSM or a cloud KMS.
type SigningKey struct {
	// Signer signs digests. Its public key must be on P-256: the server signs ES256 only.
	Signer crypto.Signer
	// KeyID is the kid of the tokens and of the published key; empty means its thumbprint.
	KeyID string
}

// LoadSigningKey reads the software key at sign_jwk_path. It belongs to the command, at the edge;
// the private key goes no further than the returned signer.
func (c *Config) LoadSigningKey() (*SigningKey, error) {
	if c.SignJwkPath == "" {
		return nil, errors.New("sign_jwk_path is required")
	}
	filename := absPath(c.BaseDir, c.SignJwkPath)
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	defer clear(raw)
	key, err := oidc.ParseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse signing key %s: %w", filename, err)
	}
	private, ok := key.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s: an EC private key on P-256 is required, not %T", filename, key.Key)
	}
	if err := checkSigningCurve(private.Public()); err != nil {
		return nil, fmt.Errorf("signing key %s: %w", filename, err)
	}
	return &SigningKey{Signer: private, KeyID: key.KeyID}, nil
}

func checkSigningCurve(public crypto.PublicKey) error {
	key, ok := public.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return errors.New("the signing key must be on P-256 (ES256)")
	}
	return nil
}

// initSigningKey takes the key the command made and publishes its public half. A server without
// one does not start (docs/design/servers.md, rule 17): a key made up here would sign tokens no
// other replica or resource server knows.
func (s *Server) initSigningKey(cfg Config) error {
	if cfg.SigningKey == nil || cfg.SigningKey.Signer == nil {
		return errors.New("no signing key")
	}
	if err := checkSigningCurve(cfg.SigningKey.Signer.Public()); err != nil {
		return err
	}
	public := jose.JSONWebKey{
		Key:       cfg.SigningKey.Signer.Public(),
		KeyID:     cfg.SigningKey.KeyID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	if public.KeyID == "" {
		kid, err := ThumbprintS256(&public)
		if err != nil {
			return err
		}
		public.KeyID = kid
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: es256OpaqueSigner{signer: cfg.SigningKey.Signer, public: public}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return fmt.Errorf("token signer: %w", err)
	}
	s.signer = signer
	s.signerKeyID = public.KeyID
	s.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}
	return nil
}

// signAccessToken signs claims as a compact JWS whose header names the published key.
func (s *Server) signAccessToken(claims map[string]any) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encode claims: %w", err)
	}
	signed, err := s.signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return []byte(compact), nil
}

// es256OpaqueSigner lets go-jose sign with the crypto.Signer without seeing the private key, which may live in an
// HSM or a KMS.
type es256OpaqueSigner struct {
	signer crypto.Signer
	public jose.JSONWebKey
}

func (s es256OpaqueSigner) Public() *jose.JSONWebKey { return &s.public }

func (s es256OpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// SignPayload signs the digest of the JWS signing input and converts the signer's ASN.1 DER to JWS's fixed-length
// R||S (RFC 7518 Section 3.4).
func (s es256OpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.ES256 {
		return nil, fmt.Errorf("the signing key signs ES256, not %s", alg)
	}
	digest := sha256.Sum256(payload)
	der, err := s.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil || len(rest) != 0 || signature.R.Sign() <= 0 || signature.S.Sign() <= 0 {
		return nil, errors.New("the signer returned a malformed ECDSA signature")
	}
	if signature.R.BitLen() > 8*es256SignatureOctets || signature.S.BitLen() > 8*es256SignatureOctets {
		return nil, errors.New("the signer returned an ECDSA signature too long for P-256")
	}
	raw := make([]byte, 2*es256SignatureOctets)
	signature.R.FillBytes(raw[:es256SignatureOctets])
	signature.S.FillBytes(raw[es256SignatureOctets:])
	return raw, nil
}
