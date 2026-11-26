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

package kv_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
)

func TestMemory_Contract(t *testing.T) {
	kvtest.Store(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_MarkerContract(t *testing.T) {
	kvtest.Marker(t, func(_ *testing.T, mark func(string, []byte) string) kv.Store {
		return kv.NewMemory(kv.WithMemoryMark(mark))
	})
}

func TestMemory_FeedContract(t *testing.T) {
	kvtest.Feed(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_TxContract(t *testing.T) {
	kvtest.Tx(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_SealedFeedContract(t *testing.T) {
	kvtest.SealedFeed(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_ResealerContract(t *testing.T) {
	kvtest.Resealer(t, func(_ *testing.T, mark func(string, []byte) string) kv.Store {
		return kv.NewMemory(kv.WithMemoryMark(mark))
	})
}
