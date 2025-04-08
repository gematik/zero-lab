package pep_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/pep"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const privateJWK1 = `{"crv":"P-256","d":"wCAQdVx6LR3BRFACmporyQ2tMGu755WNJsfhu5sx3Qk","kid":"NFXYr6yPkItn_euY_fvaiKetekY0fFcZIupXwGaesjo","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"}`
const privateJWK2 = `{"crv":"P-256","d":"hEIEtpvUJ-f3mtIn6Eqoruw8Nf8sVzPruGGThiHEGH4","kid":"QcNB-yJBGj1M0dzrWuT_Vi3_yWMWBXkznqSSY5KPcB8","kty":"EC","x":"tFrHA6uGuTvbX52h7uakJcGymGZiU5VA0gBhPEL4QoI","y":"gyo2PzEeyVTP7DdpQW3CT5T2ANLlt18tcH0H9TnfIt8"}`
const privateJWKUnknown = `{"crv":"P-256","d":"fOupVBhZroApqIqiO78XbGNT0IrIHQFvnN1UohFyEEY","kid":"FDRtW_ynysEkAlIxSLNtG6XuFeWWHDnDxP8s3GD20uo","kty":"EC","x":"QR-2W35nle5CyNXyIqW82YFlz12J0-0Ay51mpoSI6Xo","y":"qvwE7145yEDhsodww5jgfLdMAteR9y1cT1C2DBy4gCs"}`

var privateJSKSet = `{"keys":[` + privateJWK1 + "," + privateJWK2 + `]}`

const publicJSKSet = `{"keys":[{"crv":"P-256","kid":"NFXYr6yPkItn_euY_fvaiKetekY0fFcZIupXwGaesjo","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"},{"crv":"P-256","kid":"QcNB-yJBGj1M0dzrWuT_Vi3_yWMWBXkznqSSY5KPcB8","kty":"EC","x":"tFrHA6uGuTvbX52h7uakJcGymGZiU5VA0gBhPEL4QoI","y":"gyo2PzEeyVTP7DdpQW3CT5T2ANLlt18tcH0H9TnfIt8"}]}`

func createPEP(t *testing.T) *pep.PEP {
	jwkSet, err := jwk.Parse([]byte(publicJSKSet))
	if err != nil {
		t.Fatal(err)
	}

	p, err := pep.NewBuilder().
		WithJWKSet(jwkSet).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestPEPBuilder(t *testing.T) {
	jwkSet, err := jwk.Parse([]byte(publicJSKSet))
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
