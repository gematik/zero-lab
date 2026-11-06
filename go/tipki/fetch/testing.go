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

package fetch

import (
	"net/http"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// NewForTest fetches once from a test server instead of the environment's hosts, so a package built on a
// Trust can prove its checks against fetched material. base serves roots.json, list.sha2 and list.xml,
// list.sig and list.ocsp; env picks the anchors; checker answers for the TSL signer and now is the clock.
// It does not refresh in the background. Only a test holds a testing.TB, so a production path cannot
// point a Trust at other hosts.
func NewForTest(tb testing.TB, env Environment, base string, client *http.Client, checker tipki.RevocationChecker, now func() time.Time) *Trust {
	tb.Helper()
	anchor, signerAnchors, err := anchorsFor(env)
	if err != nil {
		tb.Fatal(err)
	}
	trust := newTrust(urls{roots: base + "/roots.json", hash: base + "/list.sha2", list: base + "/list"},
		anchor, signerAnchors, checker, client, now, nextFetch)
	if err := trust.refresh(tb.Context()); err != nil {
		tb.Fatal(err)
	}
	return trust
}
