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

import "crypto/mlkem"

// KEMData is a marshalled Kyber768 public key.
type KEMData []byte

// Encapsulate generates a shared secret and a ciphertext to the key.
func (kd KEMData) Encapsulate() (ss []byte, ct []byte, err error) {
	return kyberEncapsulate(kd)
}

// KEMKeyPair is a Kyber768 key pair and its public key in message form.
type KEMKeyPair struct {
	privateKey *mlkem.DecapsulationKey768
	PublicData KEMData
}

// GenerateKEMKeyPair generates a Kyber768 key pair.
func GenerateKEMKeyPair() (*KEMKeyPair, error) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &KEMKeyPair{privateKey: privateKey, PublicData: privateKey.EncapsulationKey().Bytes()}, nil
}

// Decapsulate returns the shared secret of a ciphertext to this key.
func (kp *KEMKeyPair) Decapsulate(ciphertext []byte) ([]byte, error) {
	return kyberDecapsulate(kp.privateKey, ciphertext)
}
