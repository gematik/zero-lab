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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestMemBusPubSub(t *testing.T) {
	bus := kv.NewMemBus()
	ctx := t.Context()
	ch, err := bus.Subscribe(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(ctx, "c", "hello"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got != "hello" {
			t.Errorf("got %q, want hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no message received")
	}
}

// followed returns revocations over bus and store that follow the other replicas until the test ends.
func followed(t *testing.T, bus kv.Bus, store kv.Store) *kvRevocations {
	t.Helper()
	r := kvRevocationsFor(t, bus, store)
	if err := r.Follow(t.Context()); err != nil {
		t.Fatal(err)
	}
	return r
}

func kvRevocationsFor(t *testing.T, bus kv.Bus, store kv.Store) *kvRevocations {
	t.Helper()
	r, err := newKVRevocations(bus, store, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func revoked(t *testing.T, r *kvRevocations, sid string) bool {
	t.Helper()
	got, err := r.Revoked(t.Context(), sid)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Two replicas share one bus and one store: a revocation at one reaches the other, so logout and lockout hold
// fleet-wide.
func TestRevocations_ReachTheOtherReplica(t *testing.T) {
	bus := kv.NewMemBus()
	store := kv.NewMemory()
	a := followed(t, bus, store)
	b := followed(t, bus, store)

	if err := a.Revoke(t.Context(), "sid-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, a, "sid-1") {
		t.Fatal("revoke not applied on the originating replica")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !revoked(t, b, "sid-1") {
		if time.Now().After(deadline) {
			t.Fatal("revocation did not propagate to the other replica")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if revoked(t, b, "other") {
		t.Error("unrelated sid reported revoked")
	}
}

func TestRevocations_AFreshReplicaLoadsTheStoredOnes(t *testing.T) {
	store := kv.NewMemory()
	if err := store.Set(t.Context(), revokedPrefix+"sid-old", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, followed(t, kv.NewMemBus(), store), "sid-old") {
		t.Error("Follow did not load the stored revocations before it returned")
	}
}

// A revocation is stored until its time, when the session it ends has expired anyway.
func TestRevocations_AreStoredUntilTheirTime(t *testing.T) {
	store := kv.NewMemory()
	r := followed(t, kv.NewMemBus(), store)
	if err := r.Revoke(t.Context(), "sid-x", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(t.Context(), revokedPrefix+"sid-x"); !found {
		t.Error("Revoke did not store the revocation")
	}
	if err := r.Revoke(t.Context(), "sid-past", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(t.Context(), revokedPrefix+"sid-past"); found {
		t.Error("a revocation past its time was stored")
	}
}

// A dropped NOTIFY: the revocation is in the store but never came over the bus. Reconcile applies it.
func TestRevocations_ReconcileCatchesWhatTheBusMissed(t *testing.T) {
	store := kv.NewMemory()
	r := followed(t, kv.NewMemBus(), store)
	if err := store.Set(t.Context(), revokedPrefix+"sid-missed", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if revoked(t, r, "sid-missed") {
		t.Fatal("should not be revoked before reconcile")
	}
	if err := r.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, r, "sid-missed") {
		t.Error("reconcile did not pick up the stored entry (missed NOTIFY)")
	}
}

// The sid is recovered from its key, which a sealed store leaves in the clear.
func TestRevocations_OnASealedStoreRecoverTheSidFromItsKey(t *testing.T) {
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testRing(t, 3), sessionStorePurpose)
	r := followed(t, kv.NewMemBus(), sealed)
	if err := r.Revoke(t.Context(), "sid-x", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stored, found, _ := raw.Get(t.Context(), revokedPrefix+"sid-x")
	if !found || bytes.Equal(stored, []byte{'1'}) {
		t.Fatalf("stored %q found=%v, want a sealed record", stored, found)
	}
	if !revoked(t, followed(t, kv.NewMemBus(), sealed), "sid-x") {
		t.Fatal("a fresh replica did not load the revocation")
	}
}

// Revocation records from before the upgrade hold a bare '1' and must still count: nothing reads their value.
func TestRevocations_OnASealedStoreLoadUnsealedRecordsFromBeforeTheUpgrade(t *testing.T) {
	raw := kv.NewMemory()
	if err := raw.Set(t.Context(), revokedPrefix+"sid-old", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, followed(t, kv.NewMemBus(), kv.NewSealed(raw, testRing(t, 3), sessionStorePurpose)), "sid-old") {
		t.Fatal("a revocation from before the upgrade was lost")
	}
}

// failingBus and failingStore keep a revocation from the other replicas.
type failingBus struct{ kv.Bus }

func (failingBus) Subscribe(context.Context, string) (<-chan string, error) {
	return nil, errors.New("no bus")
}
func (failingBus) Publish(context.Context, string, string) error { return errors.New("no bus") }

type failingStore struct{ kv.Store }

func (failingStore) Set(context.Context, string, []byte, time.Duration) error {
	return errors.New("no store")
}

func (failingStore) Keys(context.Context, string) ([]string, error) {
	return nil, errors.New("no store")
}

// Server rule 14: a revocation that does not get out says why, without the sid, and holds here all the same.
func TestServerRule14_ARevocationThatFailsNamesNoSid(t *testing.T) {
	r := kvRevocationsFor(t, failingBus{}, failingStore{kv.NewMemory()})
	const sid = "sid-token-hash-value"
	err := r.Revoke(t.Context(), sid, time.Now().Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "not stored") || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), sid) {
		t.Errorf("the error holds the sid: %v", err)
	}
	if !revoked(t, r, sid) {
		t.Error("the revocation does not hold at this replica")
	}
}

// Server rule 17, fail closed: a replica that cannot follow the others' revocations does not start.
func TestServerRule17_RevocationsThatCannotBeFollowedRefuseToStart(t *testing.T) {
	if err := kvRevocationsFor(t, failingBus{}, kv.NewMemory()).Follow(t.Context()); err == nil {
		t.Error("followed without a bus")
	}
	if err := kvRevocationsFor(t, kv.NewMemBus(), failingStore{kv.NewMemory()}).Follow(t.Context()); err == nil {
		t.Error("followed without the stored revocations")
	}
}
