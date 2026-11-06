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

package titls

import (
	"sync/atomic"

	"github.com/gematik/zero-lab/go/tipki"
)

// generations numbers every snapshot a TrustSource ever holds, across sources, so a verdict reached with
// one can never be taken for another's (TLSV-050).
var generations atomic.Uint64

// TrustSource holds the ti profile's current trust material: the roots and the verified TSL's CAs. The
// host swaps in a new store when it reloads the TSL; a ti configuration reads the source at the start of
// each verification, so the new material applies from the next handshake on without rebuilding the
// tls.Config, a verification in flight finishes with the snapshot it started with, and a verdict reached
// with the old material is not reused. Safe for concurrent use.
type TrustSource struct {
	current atomic.Pointer[snapshot]
}

type snapshot struct {
	store      *tipki.TrustStore
	generation uint64
}

// NewTrustSource holds store from the start; nil while no TSL is within its grace period, which refuses
// every ti server (TLSV-033).
func NewTrustSource(store *tipki.TrustStore) *TrustSource {
	source := &TrustSource{}
	source.Swap(store)
	return source
}

// Swap makes store the current material; nil withdraws it (TLSV-033).
func (s *TrustSource) Swap(store *tipki.TrustStore) {
	s.current.Store(&snapshot{store: store, generation: generations.Add(1)})
}

// Store is the current material, nil if none.
func (s *TrustSource) Store() *tipki.TrustStore {
	return s.load().store
}

func (s *TrustSource) load() *snapshot {
	if s != nil {
		if current := s.current.Load(); current != nil {
			return current
		}
	}
	// A nil or zero TrustSource holds nothing, as NewTrustSource(nil) would.
	return &snapshot{}
}
