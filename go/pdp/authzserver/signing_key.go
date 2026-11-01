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
	"errors"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

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
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse signing key %s: %w", filename, err)
	}
	var private ecdsa.PrivateKey
	if err := jwk.Export(key, &private); err != nil {
		return nil, fmt.Errorf("signing key %s: an EC private key on P-256 is required: %w", filename, err)
	}
	if err := checkSigningCurve(private.Public()); err != nil {
		return nil, fmt.Errorf("signing key %s: %w", filename, err)
	}
	kid, _ := key.KeyID()
	return &SigningKey{Signer: &private, KeyID: kid}, nil
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
	public, err := jwk.Import(cfg.SigningKey.Signer.Public())
	if err != nil {
		return fmt.Errorf("import public key: %w", err)
	}
	kid := cfg.SigningKey.KeyID
	if kid == "" {
		if kid, err = ThumbprintS256(public); err != nil {
			return err
		}
	}
	if err := public.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("set kid: %w", err)
	}
	if err := public.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		return fmt.Errorf("set alg: %w", err)
	}
	if err := public.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return fmt.Errorf("set use: %w", err)
	}
	s.signer = cfg.SigningKey.Signer
	s.signerKeyID = kid
	s.jwks = jwk.NewSet()
	return s.jwks.AddKey(public)
}

func (s *Server) signAccessToken(token jwt.Token) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, s.signerKeyID); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}
	return jwt.Sign(token, jwt.WithKey(jwa.ES256(), s.signer, jws.WithProtectedHeaders(headers)))
}
