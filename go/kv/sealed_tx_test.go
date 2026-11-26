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
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// Server rule 5: inside a transaction too the store below sees ciphertext only, and a record written in
// one is read in one and outside it.
func TestSealed_Rule5ATransactionSealsWhatItWritesAndOpensWhatItReads(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testRing(t, testRingLine("k1", 1)), "test")
	if err := sealed.Set(ctx, "standing", []byte("of before"), 0); err != nil {
		t.Fatal(err)
	}
	err := sealed.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
		if got, found, err := tx.Get(ctx, "standing"); err != nil || !found || string(got) != "of before" {
			t.Errorf("a record of before, read in the transaction: %q, found %v, err %v", got, found, err)
		}
		if err := tx.Set(ctx, "secret", []byte("plaintext"), time.Minute); err != nil {
			return err
		}
		if set, err := tx.SetIfAbsent(ctx, "once", []byte("plaintext"), 0); err != nil || !set {
			t.Errorf("set if absent: set %v, err %v", set, err)
		}
		if got, found, err := tx.Get(ctx, "secret"); err != nil || !found || string(got) != "plaintext" {
			t.Errorf("its own write, read in the transaction: %q, found %v, err %v", got, found, err)
		}
		if got, found, err := tx.Take(ctx, "standing"); err != nil || !found || string(got) != "of before" {
			t.Errorf("taken in the transaction: %q, found %v, err %v", got, found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"secret", "once"} {
		record, found, _ := raw.Get(ctx, key)
		if !found || bytes.Contains(record, []byte("plaintext")) {
			t.Errorf("%s: the store below holds the value in the clear, or nothing", key)
		}
		if got, found, err := sealed.Get(ctx, key); err != nil || !found || string(got) != "plaintext" {
			t.Errorf("%s, read outside the transaction: %q, found %v, err %v", key, got, found, err)
		}
	}
	if _, found, _ := sealed.Get(ctx, "standing"); found {
		t.Error("the taken record is still there")
	}
}

// A record that was moved under another key in the store below does not open in a transaction either.
func TestSealed_ATransactionDetectsAMovedRecord(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testRing(t, testRingLine("k1", 1)), "test")
	if err := sealed.Set(ctx, "a", []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	record, _, _ := raw.Get(ctx, "a")
	if err := raw.Set(ctx, "b", record, 0); err != nil {
		t.Fatal(err)
	}
	err := sealed.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
		_, _, err := tx.Get(ctx, "b")
		return err
	})
	if !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v", err)
	}
}

// An event a transaction of a sealed store publishes is sealed: the store below holds no payload in the
// clear, and a follower of the sealed store reads it.
func TestSealed_Rule5ATransactionSealsTheEventItPublishes(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testRing(t, testRingLine("k1", 1)), "test")
	err := sealed.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
		if err := tx.Set(ctx, "revoked:sid", []byte("r"), time.Minute); err != nil {
			return err
		}
		return tx.Publish(ctx, "revocations", []byte("who was revoked"), time.Minute)
	})
	if err != nil {
		t.Fatal(err)
	}
	follow, cancel := context.WithCancel(ctx)
	defer cancel()
	below, err := raw.(kv.Feed).Follow(follow, "revocations", 0)
	if err != nil {
		t.Fatal(err)
	}
	if e := <-below; e.Cursor != 1 || bytes.Contains(e.Payload, []byte("who was revoked")) {
		t.Fatalf("the store below holds event %d in the clear", e.Cursor)
	}
	opened, err := sealed.(kv.Feed).Follow(follow, "revocations", 0)
	if err != nil {
		t.Fatal(err)
	}
	if e := <-opened; e.Cursor != 1 || string(e.Payload) != "who was revoked" {
		t.Fatalf("the follower of the sealed store got event %d, %q", e.Cursor, e.Payload)
	}
}

type storeOnly struct{ kv.Store }

func TestSealed_ATransactionNeedsAStoreBelowThatRunsOne(t *testing.T) {
	sealed := kv.NewSealed(storeOnly{kv.NewMemory()}, testRing(t, testRingLine("k1", 1)), "test")
	err := sealed.(kv.Transactor).Tx(context.Background(), func(kv.Tx) error { return nil })
	if !errors.Is(err, kv.ErrNotTransactor) {
		t.Fatalf("got %v", err)
	}
}
