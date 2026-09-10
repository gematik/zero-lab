package gempki_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTSL_LoadsFromRef(t *testing.T) {
	testca.RequireNetwork(t)

	tslRef, err := gempki.LoadTSL(context.Background(), http.DefaultClient, gempki.URLTrustServiceListRef)
	require.NoError(t, err)

	found := false
	for _, provider := range tslRef.TrustServiceProviderList {
		for _, service := range provider.TSPServices {
			if service.ServiceInformation.ServiceTypeIdentifier == gempki.ServiceTypeCaPkc {
				found = true
			}
		}
	}
	assert.True(t, found, "the ref TSL must publish at least one CA/PKC service")

	reloaded, err := gempki.LoadTSL(context.Background(), http.DefaultClient, gempki.URLTrustServiceListRef)
	require.NoError(t, err)
	assert.Equal(t, tslRef.Hash, reloaded.Hash, "TSL hash must be stable across reloads")
}
