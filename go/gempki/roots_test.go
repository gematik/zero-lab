package gempki_test

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
)

func TestRoots(t *testing.T) {

	tsl, err := gempki.LoadTSL(gempki.URLTrustServiceListRef)
	if err != nil {
		t.Fatalf("loading TSL: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: gempki.RootsRef.BuildCertPool(tsl),
			},
		},
	}

	resp, err := httpClient.Get("https://epa-as-1.dev.epa4all.de/")
	if err != nil {
		t.Fatalf("sending request to EPA: %v", err)
	}
	t.Logf("Response: %v", resp)

}
