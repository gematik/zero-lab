package gempki_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
)

func TestTSL(t *testing.T) {
	tslRef, err := gempki.LoadTSL(gempki.URLTrustServiceListRef)
	if err != nil {
		t.Fatalf("LoadTSL failed: %v", err)
	}

	ok := false
	for _, provider := range tslRef.TrustServiceProviderList {
		for _, service := range provider.TSPServices {
			if service.ServiceInformation.ServiceTypeIdentifier == gempki.Svctype_CA_PKC {
				ok = true
				break
			}
		}
	}
	if !ok {
		t.Fatalf("CA_PKC not found")
	}
}
