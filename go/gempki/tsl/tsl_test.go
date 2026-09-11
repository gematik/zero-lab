package tsl_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/tsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTSL_LoadsFromRef(t *testing.T) {
	testca.RequireNetwork(t)

	tslRef, err := tsl.Load(context.Background(), http.DefaultClient, tsl.URLRef)
	require.NoError(t, err)

	found := false
	for _, provider := range tslRef.TrustServiceProviderList {
		for _, service := range provider.TSPServices {
			if service.ServiceInformation.ServiceTypeIdentifier == tsl.ServiceTypeCaPkc {
				found = true
			}
		}
	}
	assert.True(t, found, "the ref TSL must publish at least one CA/PKC service")

	reloaded, err := tsl.Load(context.Background(), http.DefaultClient, tsl.URLRef)
	require.NoError(t, err)
	assert.Equal(t, tslRef.Hash, reloaded.Hash, "TSL hash must be stable across reloads")
}
