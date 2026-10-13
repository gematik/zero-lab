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

import (
	"math/big"
	"sync"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiat"
)

// brainpoolP256r1 domain parameters (RFC 5639 §3.4), random ("r1") form.
//
// The field prime p lives in the fiat package. Here we materialise the curve
// equation coefficients a and b (note a ≠ −3, so the general complete addition
// formula is required) and the group order n.
const (
	hexA  = "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"
	hexB  = "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"
	hexGx = "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"
	hexGy = "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
	hexN  = "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
)

var (
	curveConstsOnce sync.Once
	feA, feB, feB3  *fiat.Element

	genOnce  sync.Once
	genBytes []byte
)

func curveConsts() (a, b, b3 *fiat.Element) {
	curveConstsOnce.Do(func() {
		feA = mustElement(hexA)
		feB = mustElement(hexB)
		// b3 = 3b mod p.
		feB3 = new(fiat.Element).Add(feB, feB)
		feB3.Add(feB3, feB)
	})
	return feA, feB, feB3
}

// generatorBytes returns the SEC1 uncompressed encoding (0x04 ‖ Gx ‖ Gy) of the
// curve generator.
func generatorBytes() []byte {
	genOnce.Do(func() {
		buf := make([]byte, 0, 1+2*fiat.ElementLen)
		buf = append(buf, 0x04)
		buf = append(buf, hexToFixed(hexGx)...)
		buf = append(buf, hexToFixed(hexGy)...)
		genBytes = buf
	})
	return genBytes
}

func mustElement(hexStr string) *fiat.Element {
	e, err := new(fiat.Element).SetBytes(hexToFixed(hexStr))
	if err != nil {
		panic("bp256: invalid constant " + hexStr + ": " + err.Error())
	}
	return e
}

// hexToFixed decodes a hex string into a left-zero-padded ElementLen byte slice.
func hexToFixed(hexStr string) []byte {
	v, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("bp256: bad hex constant " + hexStr)
	}
	out := make([]byte, fiat.ElementLen)
	v.FillBytes(out)
	return out
}
