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

package oidf

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"

	"github.com/go-jose/go-jose/v4"
)

// Keys are the relying party's private keys, as functions: a key in an HSM serves as well as one in memory, and no
// private key part passes through this package (keys.md rule 1). gemSpec_IDP_FD A_23196 allows only P-256 keys for
// TLS authentication, ID token encryption and the entity statement's signature. A_28208 asks for kids in the UUIDv7
// format for newly created keys; the kids are taken as the host gives them.
type Keys struct {
	// Sign signs the entity statement and the signed JWKS, ES256 only. A crypto.Signer takes no context, so Sign
	// bounds its own operations (an HSM client's timeouts): a Sign that hangs holds up every signing after it.
	Sign    crypto.Signer
	SignKID string
	// Decrypt agrees the content key of the ID token, ECDH-ES with A256GCM only (A_23194, A_23195).
	Decrypt    KeyAgreement
	DecryptKID string
	// Client authenticates the relying party at the IDP by self_signed_tls_client_auth. Its PrivateKey is a
	// crypto.Signer, and its Leaf is published as x5c (A_23183).
	Client    tls.Certificate
	ClientKID string
}

// KeyAgreement is the ID token key: an elliptic-curve Diffie-Hellman key agreement, which ECDH-ES is. It is
// satisfied by *ecdh.PrivateKey and by an HSM wrapper.
type KeyAgreement interface {
	Public() crypto.PublicKey
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
}

// ErrKeys is a set of keys New refuses.
var ErrKeys = errors.New("keys refused")

// check refuses keys the relying party cannot use as A_23196 requires, so that a wrong key stops the start instead
// of the first login (servers.md rule 17).
func (k Keys) check() error {
	if k.SignKID == "" || k.DecryptKID == "" || k.ClientKID == "" {
		return fmt.Errorf("%w: every key needs its kid", ErrKeys)
	}
	// A kid selects one key (A_23195): two keys under one kid would leave the IDP to guess.
	if k.SignKID == k.DecryptKID || k.SignKID == k.ClientKID || k.DecryptKID == k.ClientKID {
		return fmt.Errorf("%w: two keys share a kid", ErrKeys)
	}
	return k.checkKeys()
}

// checkKeys is check without the kids.
func (k Keys) checkKeys() error {
	if isNil(k.Sign) {
		return fmt.Errorf("%w: no signing key", ErrKeys)
	}
	if !isP256(k.Sign.Public()) {
		return fmt.Errorf("%w: the signing key is no P-256 key", ErrKeys)
	}
	if isNil(k.Decrypt) {
		return fmt.Errorf("%w: no ID token key", ErrKeys)
	}
	if _, err := decryptionPublicKey(k.Decrypt); err != nil {
		return err
	}
	return checkClientCertificate(k.Client)
}

// checkClientCertificate takes a certificate whose key signs as a crypto.Signer, is P-256 and is the key of the
// Leaf that is presented and published.
func checkClientCertificate(certificate tls.Certificate) error {
	if certificate.Leaf == nil || len(certificate.Certificate) == 0 {
		return fmt.Errorf("%w: the client certificate has no parsed Leaf", ErrKeys)
	}
	if !bytes.Equal(certificate.Certificate[0], certificate.Leaf.Raw) {
		return fmt.Errorf("%w: the client certificate's Leaf is not the certificate it presents", ErrKeys)
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok || isNil(signer) {
		return fmt.Errorf("%w: the client certificate's key is no crypto.Signer", ErrKeys)
	}
	public, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return fmt.Errorf("%w: the client certificate's key is no P-256 key", ErrKeys)
	}
	if !public.Equal(certificate.Leaf.PublicKey) {
		return fmt.Errorf("%w: the client certificate is not of its key", ErrKeys)
	}
	return nil
}

// isNil reports a key that is missing, also as a nil pointer of a key type, whose Public would panic.
func isNil(key any) bool {
	if key == nil {
		return true
	}
	value := reflect.ValueOf(key)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func isP256(public crypto.PublicKey) bool {
	key, ok := public.(*ecdsa.PublicKey)
	return ok && key.Curve == elliptic.P256()
}

// decryptionPublicKey is the public half of the ID token key as a P-256 ECDH key; an HSM wrapper may give it as an
// ECDSA key of the same curve.
func decryptionPublicKey(agreement KeyAgreement) (*ecdh.PublicKey, error) {
	switch public := agreement.Public().(type) {
	case *ecdh.PublicKey:
		if public.Curve() == ecdh.P256() {
			return public, nil
		}
	case *ecdsa.PublicKey:
		if public.Curve == elliptic.P256() {
			return public.ECDH()
		}
	}
	return nil, fmt.Errorf("%w: the ID token key is no P-256 key", ErrKeys)
}

// encryptionPublicKey is the public half of the ID token key as the ECDSA key a JWK is made of.
func encryptionPublicKey(agreement KeyAgreement) (*ecdsa.PublicKey, error) {
	public, err := decryptionPublicKey(agreement)
	if err != nil {
		return nil, err
	}
	encryption, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), public.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: the ID token key: %w", ErrKeys, err)
	}
	return encryption, nil
}

// thumbprint is the RFC 7638 SHA-256 thumbprint of public, base64url without padding: the kid of a key whose
// configuration names none. A registered relying party's kid is what the master knows it by, so it must not change
// with the library behind it.
func thumbprint(public crypto.PublicKey) (string, error) {
	sum, err := (&jose.JSONWebKey{Key: public}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", ErrKeys, err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// publishedKeys are the public keys the entity statement names: the signing key in its jwks, and in the
// openid_relying_party jwks the ID token key (A_23194) and the client certificate as x5c (A_23183).
func (k Keys) publishedKeys() (statement, relyingParty *jose.JSONWebKeySet, err error) {
	encryption, err := encryptionPublicKey(k.Decrypt)
	if err != nil {
		return nil, nil, err
	}
	statement = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: k.Sign.Public(), KeyID: k.SignKID, Use: "sig", Algorithm: string(jose.ES256)},
	}}
	relyingParty = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: encryption, KeyID: k.DecryptKID, Use: "enc", Algorithm: string(jose.ECDH_ES)},
		{
			Key: k.Client.Leaf.PublicKey, KeyID: k.ClientKID, Use: "sig", Algorithm: string(jose.ES256),
			Certificates: []*x509.Certificate{k.Client.Leaf},
		},
	}}
	return statement, relyingParty, nil
}
