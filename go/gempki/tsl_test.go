package gempki_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTSL(t *testing.T) {
	tslRef, err := gempki.LoadTSL(context.Background(), http.DefaultClient, gempki.URLTrustServiceListRef)
	if err != nil {
		t.Fatalf("LoadTSL failed: %v", err)
	}

	ok := false
	for _, provider := range tslRef.TrustServiceProviderList {
		for _, service := range provider.TSPServices {
			if service.ServiceInformation.ServiceTypeIdentifier == gempki.ServiceTypeCaPkc {
				ok = true
				break
			}
		}
	}
	if !ok {
		t.Fatalf("CA_PKC not found")
	}
}

func TestTslReload(t *testing.T) {
	tslRef, err := gempki.LoadTSL(context.Background(), http.DefaultClient, gempki.URLTrustServiceListRef)
	require.NoError(t, err, "LoadTSL failed")

	tslRefReloaded, err := gempki.LoadTSL(context.Background(), http.DefaultClient, gempki.URLTrustServiceListRef)
	require.NoError(t, err, "reloading TSL failed")

	assert.Equal(t, tslRef.Hash, tslRefReloaded.Hash, "TSL hash mismatch after reload")

	tslRefReloaded2, err := gempki.UpdateTSL(context.Background(), http.DefaultClient, tslRef)
	require.NoError(t, err, "updating TSL failed")

	assert.Same(t, tslRef, tslRefReloaded2, "TSL reference should be the same after update")
}
