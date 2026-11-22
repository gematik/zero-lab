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

package main

import (
	"log/slog"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	sharedrevoked "github.com/gematik/zero-lab/go/kv/revoked"
	"github.com/gematik/zero-lab/go/pep"
	"github.com/gematik/zero-lab/go/pep/proxy"
)

// revokedPrefix namespaces the stored revocations in kv, one key per revoked sid; zaddy reads them there.
const revokedPrefix = pep.SessionRevocationsKeyPrefix

// kvRevocations implement proxy.Revocations across replicas, and for zaddy, through the shared set of kv/revoked:
// each revocation is published on the bus and stored under its sid, from which a fresh replica loads them and
// every replica reconciles periodically. Reads come from the local set alone.
type kvRevocations = sharedrevoked.Set

var _ proxy.Revocations = (*kvRevocations)(nil)

// newKVRevocations shares the revocations over bus and store under the names zaddy reads. ttl is how long a
// revocation learned from another replica holds: the snapshot lifetime.
func newKVRevocations(bus kv.Bus, store kv.Store, ttl time.Duration, logger *slog.Logger) (*kvRevocations, error) {
	return sharedrevoked.New(sharedrevoked.Config{
		Store:   store,
		Bus:     bus,
		Prefix:  revokedPrefix,
		Channel: pep.SessionRevocationsChannel,
		TTL:     ttl,
		Logger:  logger,
	})
}
