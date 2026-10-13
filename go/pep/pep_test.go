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

package pep_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/pep"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const privateJWK1 = `{"crv":"P-256","d":"wCAQdVx6LR3BRFACmporyQ2tMGu755WNJsfhu5sx3Qk","kid":"NFXYr6yPkItn_euY_fvaiKetekY0fFcZIupXwGaesjo","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"}`

// const privateJWK2 = `{"crv":"P-256","d":"hEIEtpvUJ-f3mtIn6Eqoruw8Nf8sVzPruGGThiHEGH4","kid":"QcNB-yJBGj1M0dzrWuT_Vi3_yWMWBXkznqSSY5KPcB8","kty":"EC","x":"tFrHA6uGuTvbX52h7uakJcGymGZiU5VA0gBhPEL4QoI","y":"gyo2PzEeyVTP7DdpQW3CT5T2ANLlt18tcH0H9TnfIt8"}`
const privateJWKUnknown = `{"crv":"P-256","d":"fOupVBhZroApqIqiO78XbGNT0IrIHQFvnN1UohFyEEY","kid":"FDRtW_ynysEkAlIxSLNtG6XuFeWWHDnDxP8s3GD20uo","kty":"EC","x":"QR-2W35nle5CyNXyIqW82YFlz12J0-0Ay51mpoSI6Xo","y":"qvwE7145yEDhsodww5jgfLdMAteR9y1cT1C2DBy4gCs"}`

//var privateJSKSet = `{"keys":[` + privateJWK1 + "," + privateJWK2 + `]}`

const publicJWSKSet = `{"keys":[{"crv":"P-256","kid":"NFXYr6yPkItn_euY_fvaiKetekY0fFcZIupXwGaesjo","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"},{"crv":"P-256","kid":"QcNB-yJBGj1M0dzrWuT_Vi3_yWMWBXkznqSSY5KPcB8","kty":"EC","x":"tFrHA6uGuTvbX52h7uakJcGymGZiU5VA0gBhPEL4QoI","y":"gyo2PzEeyVTP7DdpQW3CT5T2ANLlt18tcH0H9TnfIt8"}]}`

func createPEP(t *testing.T) *pep.PEP {
	jwkSet, err := jwk.Parse([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}

	p, err := pep.NewBuilder().
		Resource("https://example.com").
		WithJWKSet(jwkSet).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestPEPBuilder(t *testing.T) {
	jwkSet, err := jwk.Parse([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}

	pep, err := pep.NewBuilder().
		WithJWKSet(jwkSet).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("PEP: %v", pep)
}
