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
