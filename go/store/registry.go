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

package store

// Kind says whether a namespace's records are sealed (STORE-021).
type Kind int

const (
	// Sealed records need a keyring.
	Sealed Kind = iota
	// Plain records hold data its consumer verifies on every read (STORE-025).
	Plain
)

// Database names the file a namespace lives in (STORE-021).
type Database int

const (
	// StateDB is state.db: kept.
	StateDB Database = iota
	// CacheDB is cache.db: may be lost at any time.
	CacheDB
)

// Namespace is a registered namespace and its record type (STORE-022).
type Namespace struct {
	Name     string
	Kind     Kind
	Database Database
	// MaxTTL is the longest lifetime of a record in seconds; 0 for none.
	MaxTTL   int64
	Fields   []string
	Requires Capabilities
}

const day = 86400

// The namespace registry of spec/store.
var (
	OAuthAccess  = Namespace{Name: "oauth.access", Kind: Sealed, Database: StateDB, MaxTTL: day, Fields: []string{"issuer", "audience", "subject"}}
	OAuthRefresh = Namespace{Name: "oauth.refresh", Kind: Sealed, Database: StateDB, MaxTTL: 90 * day, Fields: []string{"issuer", "subject"}}
	PoPP         = Namespace{Name: "popp", Kind: Sealed, Database: StateDB, MaxTTL: day, Fields: []string{"kvnr", "iccsn"}}
	Comfort      = Namespace{Name: "comfort", Kind: Sealed, Database: StateDB, Fields: []string{"konnektor"}}
	TSLState     = Namespace{Name: "tsl.state", Kind: Sealed, Database: StateDB}
	WellKnown    = Namespace{Name: "well-known", Kind: Plain, Database: CacheDB, MaxTTL: 7 * day, Fields: []string{"issuer"}}
	PKITSL       = Namespace{Name: "pki.tsl", Kind: Plain, Database: CacheDB, MaxTTL: 30 * day}
	PKIRoots     = Namespace{Name: "pki.roots", Kind: Plain, Database: CacheDB, MaxTTL: 30 * day}
	PKIOCSP      = Namespace{Name: "pki.ocsp", Kind: Plain, Database: CacheDB, MaxTTL: 7 * day, Fields: []string{"issuer"}}
	ConnectorSDS = Namespace{Name: "connector.sds", Kind: Plain, Database: CacheDB, MaxTTL: day}
)

// Registry lists every registered namespace.
func Registry() []Namespace {
	return []Namespace{OAuthAccess, OAuthRefresh, PoPP, Comfort, TSLState, WellKnown, PKITSL, PKIRoots, PKIOCSP, ConnectorSDS}
}
