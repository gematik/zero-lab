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

package kv

import "errors"

// Durability is what a store promises of a write once the call has returned. The two classes are for two
// kinds of data: what must not be lost or doubled (single-use values, sessions, registrations: server rule
// 11), and what a loss only costs a fetch (verified documents, mirrors of state kept elsewhere: server rule
// 12). A consumer of the first kind checks the class of the store it is given at start, and refuses the
// other.
type Durability int

const (
	// Durable: the write is committed and survives a crash of the database.
	Durable Durability = iota
	// Ephemeral: the write is atomic and seen by every replica at once, but may be lost when the database
	// crashes or fails over. In exchange a backend may write it faster.
	Ephemeral
)

func (d Durability) String() string {
	if d == Ephemeral {
		return "ephemeral"
	}
	return "durable"
}

// Classed is a store that says which class it is of. The stores of this module and its backends are; a
// store that wraps another passes the class of the one below on.
type Classed interface {
	Durability() Durability
}

// DurabilityOf is the class of a store. A store that does not say is durable, as every store was before
// there were classes: a wrapper around an ephemeral store that does not pass its class on would be taken
// for durable, so wrappers do.
func DurabilityOf(s Store) Durability {
	if classed, ok := s.(Classed); ok {
		return classed.Durability()
	}
	return Durable
}

// ErrEphemeralEvent is what an ephemeral store returns for an event: the feed is durable, and a transaction
// is of one class. What is written with an event is written to a durable store.
var ErrEphemeralEvent = errors.New("kv: an ephemeral store publishes no events: the feed is durable")

// ephemeralPurpose is what the purpose of a sealed store over an ephemeral one is extended by, so that a
// record sealed for one class does not open in the other.
const ephemeralPurpose = "\x00ephemeral"
