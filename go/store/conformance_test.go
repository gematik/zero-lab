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

package store_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/store"
	"github.com/gematik/zero-lab/go/store/filestore"
	"github.com/gematik/zero-lab/go/store/storetest"
)

const manifest = "../../spec/store/testdata/manifest.json"

// backends: the files backend for real, in a temporary directory; the memory backend for
// the SQLite scenarios, whose semantics it shares. The SQLite backend itself runs them in
// go/sqlitestore.
func backends(t *testing.T) storetest.Backends {
	return func(name string) (store.Backend, func(), error) {
		switch name {
		case "files":
			b, err := filestore.Open(t.TempDir())
			if err != nil {
				return nil, nil, err
			}
			return b, func() { _ = b.Close() }, nil
		case "sqlite":
			return store.NewMemoryBackend(), func() {}, nil
		}
		return nil, nil, nil
	}
}

// TestSTORE_Corpus runs every case of spec/store but the SQLite backend's capabilities,
// which the memory backend does not have; go/sqlitestore checks those.
func TestSTORE_Corpus(t *testing.T) {
	storetest.RunCorpus(t, manifest, func(c storetest.Case) bool {
		return c.Kind != "capabilities" || c.Input["backend"] != "sqlite"
	}, backends(t))
}
