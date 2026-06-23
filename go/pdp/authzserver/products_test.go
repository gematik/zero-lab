package authzserver

import (
	"slices"
	"testing"
)

func TestAllASRedirectURIs_Dedup(t *testing.T) {
	reg := NewProductsRegistry([]*Product{
		{ProductID: "a", ASRedirectURIs: []string{"https://x/cb", "https://y/cb"}},
		{ProductID: "b", ASRedirectURIs: []string{"https://y/cb", "https://z/cb"}}, // y overlaps
		{ProductID: "c"}, // none
	})

	got := reg.AllASRedirectURIs()
	if len(got) != 3 {
		t.Fatalf("AllASRedirectURIs = %v, want 3 deduped", got)
	}
	for _, want := range []string{"https://x/cb", "https://y/cb", "https://z/cb"} {
		if !slices.Contains(got, want) {
			t.Errorf("AllASRedirectURIs missing %q (got %v)", want, got)
		}
	}
}
