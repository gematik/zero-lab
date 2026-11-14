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
	"crypto"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

const (
	// contentKeyBytes is the key length of A256GCM, the only content encryption registered.
	contentKeyBytes = 32
	// maxPartyInfoBytes bounds apu and apv, which the IDP chooses and nothing here needs to be long.
	maxPartyInfoBytes = 1024
	// p256CoordinateBytes is the length of a P-256 coordinate and of its ECDH shared secret.
	p256CoordinateBytes = 32
)

// ErrIDTokenEncryption is an encrypted ID token the relying party refuses before or while agreeing its key.
var ErrIDTokenEncryption = errors.New("ID token encryption refused")

// opaqueDecrypter derives the content key of an ECDH-ES JWE through a KeyAgreement, so the ID token key may live in
// an HSM (keys.md rule 1). It takes only what the relying party registers: alg ECDH-ES, enc A256GCM, and its own
// key by kid (A_23195).
type opaqueDecrypter struct {
	agreement KeyAgreement
	kid       string
}

var _ jose.OpaqueKeyDecrypter = opaqueDecrypter{}

// DecryptKey implements jose.OpaqueKeyDecrypter. With ECDH-ES the agreement is the key itself, so there is no
// encrypted key (RFC 7518 §4.6).
func (d opaqueDecrypter) DecryptKey(encryptedKey []byte, header jose.Header) ([]byte, error) {
	if header.Algorithm != string(jose.ECDH_ES) {
		return nil, fmt.Errorf("%w: alg is not ECDH-ES", ErrIDTokenEncryption)
	}
	if len(encryptedKey) != 0 {
		return nil, fmt.Errorf("%w: ECDH-ES carries no encrypted key", ErrIDTokenEncryption)
	}
	// A_23195: decrypted with the key the header's kid names; a token without kid can only mean the one key.
	if header.KeyID != "" && header.KeyID != d.kid {
		return nil, fmt.Errorf("%w: kid names another key", ErrIDTokenEncryption)
	}
	if enc, _ := header.ExtraHeaders["enc"].(string); enc != string(jose.A256GCM) {
		return nil, fmt.Errorf("%w: enc is not A256GCM", ErrIDTokenEncryption)
	}
	if _, compressed := header.ExtraHeaders["zip"]; compressed {
		return nil, fmt.Errorf("%w: compressed", ErrIDTokenEncryption)
	}
	epk, err := ephemeralPublicKey(header.ExtraHeaders["epk"])
	if err != nil {
		return nil, err
	}
	apu, err := partyInfo(header.ExtraHeaders, "apu")
	if err != nil {
		return nil, err
	}
	apv, err := partyInfo(header.ExtraHeaders, "apv")
	if err != nil {
		return nil, err
	}

	z, err := d.agreement.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("%w: key agreement: %w", ErrIDTokenEncryption, err)
	}
	if len(z) != p256CoordinateBytes {
		return nil, fmt.Errorf("%w: key agreement gave %d bytes", ErrIDTokenEncryption, len(z))
	}
	return concatKDF(z, string(jose.A256GCM), apu, apv), nil
}

// concatKDF is the Concat KDF of RFC 7518 §4.6.2 with SHA-256, as go-jose's DeriveECDHES builds it: AlgorithmID,
// PartyUInfo and PartyVInfo each prefixed with their 32-bit big-endian length, SuppPubInfo the key length in bits,
// SuppPrivInfo empty. With ECDH-ES direct the AlgorithmID is the enc value.
func concatKDF(z []byte, algorithmID string, apu, apv []byte) []byte {
	suppPubInfo := binary.BigEndian.AppendUint32(nil, contentKeyBytes*8)
	reader := josecipher.NewConcatKDF(crypto.SHA256, z,
		lengthPrefixed([]byte(algorithmID)), lengthPrefixed(apu), lengthPrefixed(apv), suppPubInfo, []byte{})
	key := make([]byte, contentKeyBytes)
	// The KDF reads from a hash and does not fail.
	_, _ = io.ReadFull(reader, key)
	return key
}

func lengthPrefixed(data []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(data))), data...)
}

// ephemeralPublicKey reads the epk header (RFC 7518 §4.6.1.1) as a public P-256 key. ecdh.P256().NewPublicKey refuses
// a point off the curve, with which an invalid-curve attack would learn the private key (RFC 8725 §3.4).
func ephemeralPublicKey(member any) (*ecdh.PublicKey, error) {
	jwk, ok := member.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: no epk", ErrIDTokenEncryption)
	}
	if _, private := jwk["d"]; private {
		return nil, fmt.Errorf("%w: epk holds a private key", ErrIDTokenEncryption)
	}
	if kty, _ := jwk["kty"].(string); kty != "EC" {
		return nil, fmt.Errorf("%w: epk is no EC key", ErrIDTokenEncryption)
	}
	if crv, _ := jwk["crv"].(string); crv != "P-256" {
		return nil, fmt.Errorf("%w: epk is no P-256 key", ErrIDTokenEncryption)
	}
	x, err := coordinate(jwk, "x")
	if err != nil {
		return nil, err
	}
	y, err := coordinate(jwk, "y")
	if err != nil {
		return nil, err
	}
	point := append(append([]byte{4}, x...), y...)
	public, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("%w: epk is no point of P-256", ErrIDTokenEncryption)
	}
	return public, nil
}

// coordinate is a P-256 coordinate of a JWK, base64url without padding and exactly 32 bytes (RFC 7518 §6.2.1.2).
func coordinate(jwk map[string]any, name string) ([]byte, error) {
	encoded, ok := jwk[name].(string)
	if !ok {
		return nil, fmt.Errorf("%w: epk has no %s", ErrIDTokenEncryption, name)
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) != p256CoordinateBytes {
		return nil, fmt.Errorf("%w: epk %s is no P-256 coordinate", ErrIDTokenEncryption, name)
	}
	return value, nil
}

// partyInfo is the optional apu or apv header, base64url and at most maxPartyInfoBytes decoded.
func partyInfo(headers map[jose.HeaderKey]any, name jose.HeaderKey) ([]byte, error) {
	member, present := headers[name]
	if !present {
		return nil, nil
	}
	encoded, ok := member.(string)
	if !ok || base64.RawURLEncoding.DecodedLen(len(encoded)) > maxPartyInfoBytes {
		return nil, fmt.Errorf("%w: %s is no base64url of at most %d bytes", ErrIDTokenEncryption, name, maxPartyInfoBytes)
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is no base64url", ErrIDTokenEncryption, name)
	}
	return value, nil
}
