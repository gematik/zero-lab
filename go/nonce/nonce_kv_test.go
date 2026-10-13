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

package nonce_test

import (
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
)

func TestKVService_GetRedeemSingleUse(t *testing.T) {
	svc := nonce.NewKVService(kv.NewMemory(), time.Minute)

	n, err := svc.Get()
	if err != nil || n == "" {
		t.Fatalf("get: %v %q", err, n)
	}
	if err := svc.Redeem(n); err != nil {
		t.Fatalf("first redeem should succeed: %v", err)
	}
	if err := svc.Redeem(n); err == nil {
		t.Fatal("second redeem should fail (single-use)")
	}
	if err := svc.Redeem("never-issued"); err == nil {
		t.Fatal("unknown nonce should fail")
	}
}

func TestKVService_Expiry(t *testing.T) {
	svc := nonce.NewKVService(kv.NewMemory(), 20*time.Millisecond)
	n, _ := svc.Get()
	time.Sleep(40 * time.Millisecond)
	if err := svc.Redeem(n); err == nil {
		t.Fatal("expired nonce should not redeem")
	}
}
