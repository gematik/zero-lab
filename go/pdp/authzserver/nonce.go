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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
)

const (
	// nonceServicePurpose names the client-assertion nonces in the key derivation.
	nonceServicePurpose = "pdp/client-assertion"
	// nonceClockSkew outlasts the difference between the replicas' clocks: a replica behind the one that
	// recorded a nonce still sees it as unexpired for that much longer, and the record must still be there.
	nonceClockSkew = time.Minute
)

// recordNonce keeps an accepted nonce in store until it expires, so that its single use holds across replicas.
// Nothing is written before a nonce is accepted, so an anonymous GET of the nonce endpoint costs no write.
func recordNonce(store kv.Store) nonce.Record {
	return func(ctx context.Context, id string, until time.Time) (bool, error) {
		// max: a TTL of zero or below would mean a record that never expires.
		ttl := max(time.Until(until), 0) + nonceClockSkew
		return store.SetIfAbsent(ctx, "nonce:"+id, []byte{1}, ttl)
	}
}

// NonceEndpoint returns a fresh replay nonce as a text/plain body (GET only).
func (s *Server) NonceEndpoint(w http.ResponseWriter, _ *http.Request) error {
	nonce, err := s.nonceService.Get()
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to get nonce: %v", err))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(nonce))
	return nil
}
