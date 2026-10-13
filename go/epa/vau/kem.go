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
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

type KEMData []byte

func (kd KEMData) PublicKey() (kem.PublicKey, error) {
	return kyber768.Scheme().UnmarshalBinaryPublicKey(kd)
}

// Encapsulate generates a shared secret and a ciphertext
func (kd KEMData) Encapsulate() (ss []byte, ct []byte, err error) {
	publicKey, err := kd.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	// Attention: ct and ss are not in the same order as in ECDHData.Encapsulate
	ct, ss, err = publicKey.Scheme().Encapsulate(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return ss, ct, nil
}

type KEMKeyPair struct {
	privateKey kem.PrivateKey
	PublicData KEMData
}

func GenerateKEMKeyPair(scheme kem.Scheme) (*KEMKeyPair, error) {
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	publicData, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &KEMKeyPair{
		privateKey: privateKey,
		PublicData: publicData,
	}, nil
}

func (kp *KEMKeyPair) Decapsulate(ciphertext []byte) ([]byte, error) {
	return kp.privateKey.Scheme().Decapsulate(kp.privateKey, ciphertext)
}
