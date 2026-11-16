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

package vau

import (
	"crypto/mlkem"
	"crypto/sha3"
	"errors"
)

// The ePA VAU protocol asks for Kyber768 in its round 3 version 3.02 (gemSpec_Krypt A_24425-01, A_24428,
// [IETF-Kyber] draft-cfrg-schwabe-kyber), which FIPS 203's ML-KEM-768 changed on the wire. The two differ only
// around the core both share, so Kyber v3.02 is built here on the standard library's ML-KEM-768, as gematik's
// lib-vau does on BouncyCastle's (words.filippo.io/dispatches/mlkem768, "using a ML-KEM implementation as
// Kyber v3"):
//   - Kyber derives the shared secret as SHAKE256(K ‖ SHA3-256(c)), where ML-KEM returns K itself; K is the
//     same in both, the first half of SHA3-512(m ‖ H(pk)).
//   - Kyber hashes its random m once more before use; ML-KEM uses a random m directly, which no one can tell
//     from a hashed one.
//   - On a ciphertext that does not re-encrypt, both return a pseudorandom key derived from z, but not the
//     same one. Either way the AEAD keyed from it fails, so the handshake fails as it would with Kyber.
//
// Public keys (1184 bytes) and ciphertexts (1088 bytes) are encoded alike in both.

// kyberSharedSecretSize is the size of Kyber768's shared secret.
const kyberSharedSecretSize = 32

// errKyberPublicKey is a peer's Kyber768 public key that is not one.
var errKyberPublicKey = errors.New("vau: not a Kyber768 public key")

// kyberEncapsulate encapsulates a fresh shared secret to a Kyber768 public key.
func kyberEncapsulate(publicKey []byte) (sharedSecret, ciphertext []byte, err error) {
	key, err := mlkem.NewEncapsulationKey768(publicKey)
	if err != nil {
		return nil, nil, errKyberPublicKey
	}
	k, ciphertext := key.Encapsulate()
	return kyberSharedSecret(k, ciphertext), ciphertext, nil
}

// kyberDecapsulate returns the shared secret a ciphertext carries to key.
func kyberDecapsulate(key *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error) {
	k, err := key.Decapsulate(ciphertext)
	if err != nil {
		return nil, err
	}
	return kyberSharedSecret(k, ciphertext), nil
}

// kyberSharedSecret is Kyber v3.02's KDF(K ‖ H(c)): SHAKE256 to 32 bytes over K and SHA3-256 of the ciphertext.
func kyberSharedSecret(k, ciphertext []byte) []byte {
	h := sha3.Sum256(ciphertext)
	return sha3.SumSHAKE256(append(append(make([]byte, 0, len(k)+len(h)), k...), h[:]...), kyberSharedSecretSize)
}
