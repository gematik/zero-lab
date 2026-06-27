package authzserver

import (
	"slices"
	"testing"
)

func TestAllOIDCRedirectURIs_Dedup(t *testing.T) {
	reg := NewProductsRegistry([]*Product{
		{ProductID: "a", OIDCRedirectURIs: []string{"https://x/cb", "https://y/cb"}},
		{ProductID: "b", OIDCRedirectURIs: []string{"https://y/cb", "https://z/cb"}}, // y overlaps
		{ProductID: "c"}, // none
	})

	got := reg.AllOIDCRedirectURIs()
	if len(got) != 3 {
		t.Fatalf("AllOIDCRedirectURIs = %v, want 3 deduped", got)
	}
	for _, want := range []string{"https://x/cb", "https://y/cb", "https://z/cb"} {
		if !slices.Contains(got, want) {
			t.Errorf("AllOIDCRedirectURIs missing %q (got %v)", want, got)
		}
	}
}
