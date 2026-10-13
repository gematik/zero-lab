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

package bp256

import "errors"

// PublicKey returns the SEC 1 uncompressed encoding of d·G for a private
// scalar d (32-byte big-endian, in [1, n-1]), computed in constant time.
func PublicKey(d []byte) ([]byte, error) {
	dE, err := scalarFromCanonical(d)
	if err != nil || dE.IsZero() == 1 {
		return nil, errScalarRange
	}
	return new(Point).ScalarBaseMult(d).Bytes(), nil
}

// ECDH computes the brainpoolP256r1 ECDH shared secret per BSI TR-03111 §3.5.1:
// the x-coordinate of d·peer, returned as a 32-byte big-endian value. d is the
// private scalar (32-byte big-endian, in [1, n-1]); peer is the peer's public
// point in SEC 1 uncompressed encoding, validated here. It returns an error if
// the result is the point at infinity.
func ECDH(d, peer []byte) ([]byte, error) {
	if _, err := scalarFromCanonical(d); err != nil {
		return nil, err
	}
	p, err := new(Point).SetBytes(peer)
	if err != nil {
		return nil, err
	}
	if p.IsInfinity() == 1 {
		return nil, errors.New("bp256: ECDH peer is the point at infinity")
	}
	shared := new(Point).ScalarMult(p, d)
	if shared.IsInfinity() == 1 {
		return nil, errors.New("bp256: ECDH produced the point at infinity")
	}
	return shared.BytesX()
}
