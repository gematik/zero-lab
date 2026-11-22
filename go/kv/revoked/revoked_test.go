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

package revoked

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

const (
	testPrefix  = "test:revoked:"
	testChannel = "test_revoked"
)

func newSet(t *testing.T, bus kv.Bus, store kv.Store, now func() time.Time) *Set {
	t.Helper()
	s, err := New(Config{Store: store, Bus: bus, Prefix: testPrefix, Channel: testChannel, TTL: time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func following(t *testing.T, bus kv.Bus, store kv.Store) *Set {
	t.Helper()
	s := newSet(t, bus, store, nil)
	if err := s.Follow(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s
}

func isRevoked(t *testing.T, s *Set, id string) bool {
	t.Helper()
	got, err := s.Revoked(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestNew_RefusesAnIncompleteConfig(t *testing.T) {
	full := Config{Store: kv.NewMemory(), Bus: kv.NewMemBus(), Prefix: testPrefix, Channel: testChannel, TTL: time.Hour}
	for name, change := range map[string]func(*Config){
		"store":   func(c *Config) { c.Store = nil },
		"bus":     func(c *Config) { c.Bus = nil },
		"prefix":  func(c *Config) { c.Prefix = "" },
		"channel": func(c *Config) { c.Channel = "" },
		"ttl":     func(c *Config) { c.TTL = 0 },
	} {
		cfg := full
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("without %s: accepted", name)
		}
	}
	if _, err := New(full); err != nil {
		t.Fatal(err)
	}
}

// A revocation published on the bus after Follow reaches the following set without a store read.
func TestFollow_LearnsARevocationPublishedOnTheBus(t *testing.T) {
	bus := kv.NewMemBus()
	s := following(t, bus, kv.NewMemory())
	if err := bus.Publish(t.Context(), testChannel, "id-1"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !isRevoked(t, s, "id-1") {
		if time.Now().After(deadline) {
			t.Fatal("the published revocation was not learned")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if isRevoked(t, s, "other") {
		t.Error("an unrelated id is reported revoked")
	}
}

// A revocation stored before Follow holds when Follow returns; one stored later without a bus message holds
// after the next reconcile.
func TestFollow_LearnsTheStoredRevocations(t *testing.T) {
	store := kv.NewMemory()
	if err := store.Set(t.Context(), testPrefix+"id-old", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	s := following(t, kv.NewMemBus(), store)
	if !isRevoked(t, s, "id-old") {
		t.Fatal("Follow did not load the stored revocations before it returned")
	}
	if err := store.Set(t.Context(), testPrefix+"id-missed", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !isRevoked(t, s, "id-missed") {
		t.Error("reconcile did not pick up a revocation the bus missed")
	}
}

// Keys alone are read: a process without the store's key ring follows a sealed store.
func TestFollow_ReadsKeysOnlySoASealedStoreNeedsNoKeyRing(t *testing.T) {
	raw := kv.NewMemory()
	writer := newSet(t, kv.NewMemBus(), kv.NewSealed(raw, testRing(t), "test"), nil)
	if err := writer.Revoke(t.Context(), "id-x", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !isRevoked(t, following(t, kv.NewMemBus(), raw), "id-x") {
		t.Fatal("a reader of the bare store did not learn the sealed revocation")
	}
}

func TestRevoke_StoresUntilItsTimeAndPublishes(t *testing.T) {
	bus := kv.NewMemBus()
	store := kv.NewMemory()
	ch, err := bus.Subscribe(t.Context(), testChannel)
	if err != nil {
		t.Fatal(err)
	}
	s := newSet(t, bus, store, nil)
	if err := s.Revoke(t.Context(), "id-x", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(t.Context(), testPrefix+"id-x"); !found {
		t.Error("not stored")
	}
	select {
	case got := <-ch:
		if got != "id-x" {
			t.Errorf("published %q", got)
		}
	case <-time.After(time.Second):
		t.Error("not published")
	}
	if err := s.Revoke(t.Context(), "id-past", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(t.Context(), testPrefix+"id-past"); found {
		t.Error("a revocation past its time was stored")
	}
}

type failingStore struct{ kv.Store }

func (failingStore) Set(context.Context, string, []byte, time.Duration) error {
	return errors.New("no store")
}

func (failingStore) Keys(context.Context, string) ([]string, error) {
	return nil, errors.New("no store")
}

type failingBus struct{ kv.Bus }

func (failingBus) Subscribe(context.Context, string) (<-chan string, error) {
	return nil, errors.New("no bus")
}

func (failingBus) Publish(context.Context, string, string) error { return errors.New("no bus") }

// Server rule 14: a revocation that does not get out says so without the id, and holds here all the same.
func TestServerRule14_ARevocationThatFailsNamesNoID(t *testing.T) {
	s := newSet(t, failingBus{}, failingStore{kv.NewMemory()}, nil)
	const id = "id-token-hash-value"
	err := s.Revoke(t.Context(), id, time.Now().Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "not stored") || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), id) {
		t.Errorf("the error holds the id: %v", err)
	}
	if !isRevoked(t, s, id) {
		t.Error("the revocation does not hold here")
	}
}

// Server rule 17: a set that cannot follow the others says so, and the host refuses to serve.
func TestServerRule17_FollowFailsWithoutBusOrStore(t *testing.T) {
	if err := newSet(t, failingBus{}, kv.NewMemory(), nil).Follow(t.Context()); err == nil {
		t.Error("followed without a bus")
	}
	if err := newSet(t, kv.NewMemBus(), failingStore{kv.NewMemory()}, nil).Follow(t.Context()); err == nil {
		t.Error("followed without the stored revocations")
	}
}

// clock is a settable clock for the tests of staleness.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// switchableStore fails Keys once broken is set.
type switchableStore struct {
	kv.Store
	mu     sync.Mutex
	broken bool
}

func (s *switchableStore) Keys(ctx context.Context, prefix string) ([]string, error) {
	s.mu.Lock()
	broken := s.broken
	s.mu.Unlock()
	if broken {
		return nil, errors.New("no store")
	}
	return s.Store.Keys(ctx, prefix)
}

// Server rule 16: a set that has not read the stored revocations, or not for longer than MaxStale, cannot tell
// that an id is not revoked and says so with an error, on which the caller denies. What it holds stays revoked.
func TestServerRule16_AStaleSetCannotTellAnIDIsNotRevoked(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	store := &switchableStore{Store: kv.NewMemory()}
	s := newSet(t, kv.NewMemBus(), store, c.now)

	if _, err := s.Revoked(t.Context(), "id"); !errors.Is(err, ErrStale) {
		t.Fatalf("before the first read: err = %v, want ErrStale", err)
	}
	if err := s.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if isRevoked(t, s, "id") {
		t.Fatal("revoked after a fresh read of an empty store")
	}
	if err := s.Revoke(t.Context(), "held", c.now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	store.broken = true
	store.mu.Unlock()
	c.advance(DefaultReconcileEvery)
	if err := s.Reconcile(t.Context()); err == nil {
		t.Fatal("reconcile on a broken store succeeded")
	}
	if isRevoked(t, s, "id") {
		t.Fatal("one failed reconcile within MaxStale should still answer")
	}
	c.advance(3 * DefaultReconcileEvery)
	if _, err := s.Revoked(t.Context(), "id"); !errors.Is(err, ErrStale) {
		t.Errorf("past MaxStale: err = %v, want ErrStale", err)
	}
	if !isRevoked(t, s, "held") {
		t.Error("a held revocation was lost to staleness")
	}
}

func testRing(t *testing.T) *kv.Keyring {
	t.Helper()
	ring, err := kv.ParseKeyring([]byte("k1 " + base64.StdEncoding.EncodeToString(randomKey(t)) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}
