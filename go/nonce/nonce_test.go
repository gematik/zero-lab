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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/nonce"
)

type testKeys struct {
	current string
	keys    map[string][]byte
}

func (k *testKeys) Current() (string, []byte) { return k.current, bytes.Clone(k.keys[k.current]) }
func (k *testKeys) Lookup(id string) ([]byte, bool) {
	key, ok := k.keys[id]
	return bytes.Clone(key), ok
}

func keysOf(ids ...string) *testKeys {
	k := &testKeys{current: ids[0], keys: map[string][]byte{}}
	for i, id := range ids {
		k.keys[id] = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}
	return k
}

type recorder struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	err   error
	calls int
}

func newRecorder() *recorder { return &recorder{seen: map[string]time.Time{}} }

func (r *recorder) record(_ context.Context, id string, until time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return false, r.err
	}
	if _, ok := r.seen[id]; ok {
		return false, nil
	}
	r.seen[id] = until
	return true, nil
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

var start = time.Unix(1_800_000_000, 0)

func newService(t *testing.T, keys nonce.Keys, purpose string, r *recorder, c *clock) *nonce.Service {
	t.Helper()
	s, err := nonce.New(keys, purpose, time.Minute, r.record, nonce.WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRedeem_ANonceIsAcceptedOnce(t *testing.T) {
	r := newRecorder()
	s := newService(t, keysOf("k1"), "p", r, &clock{start})
	n, err := s.Get()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Redeem(context.Background(), n); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.Redeem(context.Background(), n); !errors.Is(err, nonce.ErrReplayed) {
		t.Fatalf("second: %v", err)
	}
}

func TestRedeem_SingleUseHoldsAcrossReplicasSharingKeysAndRecord(t *testing.T) {
	keys, r, c := keysOf("k1"), newRecorder(), &clock{start}
	a, b := newService(t, keys, "p", r, c), newService(t, keys, "p", r, c)
	n, _ := a.Get()
	if err := b.Redeem(context.Background(), n); err != nil {
		t.Fatalf("issued at a, redeemed at b: %v", err)
	}
	if err := a.Redeem(context.Background(), n); !errors.Is(err, nonce.ErrReplayed) {
		t.Fatalf("replayed at a: %v", err)
	}
}

func TestRedeem_ConcurrencyHasExactlyOneWinner(t *testing.T) {
	r := newRecorder()
	s := newService(t, keysOf("k1"), "p", r, &clock{start})
	n, _ := s.Get()
	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if s.Redeem(context.Background(), n) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners", wins.Load())
	}
}

func TestGet_IssuingTouchesNoStore(t *testing.T) {
	r := newRecorder()
	s := newService(t, keysOf("k1"), "p", r, &clock{start})
	for range 10 {
		if _, err := s.Get(); err != nil {
			t.Fatal(err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("Get called record %d times", r.calls)
	}
}

func TestRedeem_RecordIsKeyedByTheSHA256OfTheNonceUntilItsExpiry(t *testing.T) {
	r := newRecorder()
	c := &clock{start}
	s := newService(t, keysOf("k1"), "p", r, c)
	n, _ := s.Get()
	if err := s.Redeem(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(n))
	until, ok := r.seen[hex.EncodeToString(sum[:])]
	if !ok {
		t.Fatalf("recorded %v", r.seen)
	}
	if !until.Equal(start.Add(time.Minute)) {
		t.Fatalf("until %v, want %v", until, start.Add(time.Minute))
	}
}

func TestRedeem_ARecordFailureRefuses(t *testing.T) {
	r := newRecorder()
	s := newService(t, keysOf("k1"), "p", r, &clock{start})
	n, _ := s.Get()
	outage := errors.New("store down")
	r.err = outage
	err := s.Redeem(context.Background(), n)
	if !errors.Is(err, outage) {
		t.Fatalf("got %v", err)
	}
	if errors.Is(err, nonce.ErrInvalid) || errors.Is(err, nonce.ErrReplayed) {
		t.Fatalf("an outage reads as a bad nonce: %v", err)
	}
}

func TestRedeem_ExpiredNonceIsRefusedWithoutARecord(t *testing.T) {
	r := newRecorder()
	c := &clock{start}
	s := newService(t, keysOf("k1"), "p", r, c)
	n, _ := s.Get()
	c.now = start.Add(time.Minute)
	if err := s.Redeem(context.Background(), n); !errors.Is(err, nonce.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if r.calls != 0 {
		t.Fatal("an expired nonce reached the store")
	}
}

func TestRedeem_ANonceOfAnotherPurposeIsRefused(t *testing.T) {
	keys, r, c := keysOf("k1"), newRecorder(), &clock{start}
	n, _ := newService(t, keys, "a", r, c).Get()
	if err := newService(t, keys, "b", r, c).Redeem(context.Background(), n); !errors.Is(err, nonce.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestRedeem_AForgedOrAlteredNonceIsRefusedWithoutARecord(t *testing.T) {
	r := newRecorder()
	s := newService(t, keysOf("k1"), "p", r, &clock{start})
	n, _ := s.Get()
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		tampered := bytes.Clone(raw)
		tampered[i] ^= 0x01
		if err := s.Redeem(context.Background(), base64.RawURLEncoding.EncodeToString(tampered)); !errors.Is(err, nonce.ErrInvalid) {
			t.Fatalf("byte %d: got %v", i, err)
		}
	}
	for _, bad := range []string{"", "never-issued", strings.Repeat("A", 100_000), n[:len(n)-1]} {
		if err := s.Redeem(context.Background(), bad); !errors.Is(err, nonce.ErrInvalid) {
			t.Fatalf("%.20q: got %v", bad, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("%d bad nonces reached the store", r.calls)
	}
}

// The record is keyed by the string: a second spelling of the same bytes would be a second use. Go's base64
// decoder skips newlines and, unless strict, ignores the trailing bits of the last character.
func TestRedeem_AnotherSpellingOfANonceIsRefused(t *testing.T) {
	r := newRecorder()
	s := newService(t, keysOf("k1"), "p", r, &clock{start})
	n, _ := s.Get()
	if err := s.Redeem(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	spellings := []string{n + "\n", "\n" + n, n[:8] + "\r\n" + n[8:], n + "="}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, c := range alphabet {
		if variant := n[:len(n)-1] + string(c); variant != n {
			spellings = append(spellings, variant)
		}
	}
	for _, spelling := range spellings {
		if err := s.Redeem(context.Background(), spelling); !errors.Is(err, nonce.ErrInvalid) {
			t.Fatalf("spelling %q: got %v", spelling, err)
		}
	}
}

func TestGet_NoncesAreNQCHARAndBounded(t *testing.T) {
	long := strings.Repeat("k", nonce.MaxKeyIDLen)
	s := newService(t, keysOf(long), "p", newRecorder(), &clock{start})
	for range 100 {
		n, err := s.Get()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) > nonce.MaxEncodedLen {
			t.Fatalf("%d characters, bound %d", len(n), nonce.MaxEncodedLen)
		}
		for _, c := range []byte(n) {
			// RFC 9449 Section 8.1: NQCHAR = %x21 / %x23-5B / %x5D-7E
			if c != 0x21 && (c < 0x23 || c > 0x5B) && (c < 0x5D || c > 0x7E) {
				t.Fatalf("%q in %q is not NQCHAR", c, n)
			}
		}
	}
}

func TestGet_NoncesDiffer(t *testing.T) {
	s := newService(t, keysOf("k1"), "p", newRecorder(), &clock{start})
	a, _ := s.Get()
	b, _ := s.Get()
	if a == b {
		t.Fatal("two nonces alike")
	}
}

func TestRedeem_ANonceFromBeforeARotationStaysValid(t *testing.T) {
	r, c := newRecorder(), &clock{start}
	n, _ := newService(t, keysOf("old"), "p", r, c).Get()
	rotated := keysOf("new")
	rotated.keys["old"] = bytes.Repeat([]byte{1}, 32)
	if err := newService(t, rotated, "p", r, c).Redeem(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}

func TestRedeem_ANonceUnderADroppedKeyIsRefused(t *testing.T) {
	r, c := newRecorder(), &clock{start}
	n, _ := newService(t, keysOf("old"), "p", r, c).Get()
	if err := newService(t, keysOf("new"), "p", r, c).Redeem(context.Background(), n); !errors.Is(err, nonce.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestNew_RefusesAnIncompleteConfiguration(t *testing.T) {
	keys, record := keysOf("k1"), newRecorder().record
	if _, err := nonce.New(nil, "p", time.Minute, record); err == nil {
		t.Error("no keys")
	}
	if _, err := nonce.New(keys, "", time.Minute, record); err == nil {
		t.Error("no purpose")
	}
	if _, err := nonce.New(keys, "p", 0, record); err == nil {
		t.Error("no ttl")
	}
	if _, err := nonce.New(keys, "p", time.Minute, nil); err == nil {
		t.Error("no record")
	}
}

func TestGet_FailsOnAKeyOfTheWrongLength(t *testing.T) {
	keys := keysOf("k1")
	keys.keys["k1"] = make([]byte, 16)
	if _, err := newService(t, keys, "p", newRecorder(), &clock{start}).Get(); err == nil {
		t.Fatal("sealed under a 16-byte key")
	}
}

func newSource(t *testing.T, keys nonce.Keys, purpose string, c *clock) *nonce.Source {
	t.Helper()
	s, err := nonce.NewSource(keys, purpose, time.Minute, nonce.WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// RFC 9449 Section 8: a server nonce may be used by several proofs while it is current.
func TestSource_ANonceIsReusableWithinItsWindow(t *testing.T) {
	c := &clock{start}
	s := newSource(t, keysOf("k1"), "dpop", c)
	n, err := s.Fresh()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if !s.Valid(n) {
			t.Fatal("refused within its window")
		}
	}
	c.now = start.Add(time.Minute)
	if s.Valid(n) {
		t.Fatal("accepted after its window")
	}
}

func TestSource_ReplicasSharingKeysAcceptEachOthersNonces(t *testing.T) {
	keys, c := keysOf("k1"), &clock{start}
	n, _ := newSource(t, keys, "dpop", c).Fresh()
	if !newSource(t, keys, "dpop", c).Valid(n) {
		t.Fatal("refused at the other replica")
	}
}

func TestSource_MustMatchExactly(t *testing.T) {
	s := newSource(t, keysOf("k1"), "dpop", &clock{start})
	n, _ := s.Fresh()
	for _, bad := range []string{"", "x", n + "\n", n + "=", n[:len(n)-1], strings.Repeat("A", 100_000)} {
		if s.Valid(bad) {
			t.Fatalf("accepted %.20q", bad)
		}
	}
}

// Even under one purpose string, a nonce that is reusable must not pass as a single-use one, or the other way.
func TestSource_AndServiceDoNotAcceptEachOthersNonces(t *testing.T) {
	keys, c, r := keysOf("k1"), &clock{start}, newRecorder()
	source, service := newSource(t, keys, "same", c), newService(t, keys, "same", r, c)
	fromSource, _ := source.Fresh()
	if err := service.Redeem(context.Background(), fromSource); !errors.Is(err, nonce.ErrInvalid) {
		t.Fatalf("a source nonce redeemed: %v", err)
	}
	fromService, _ := service.Get()
	if source.Valid(fromService) {
		t.Fatal("a single-use nonce passed as a source nonce")
	}
}

func TestEphemeralKeys_AreRandomAndUsable(t *testing.T) {
	a, err := nonce.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}
	b, err := nonce.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, keyA := a.Current()
	_, keyB := b.Current()
	if len(keyA) != 32 || bytes.Equal(keyA, keyB) {
		t.Fatal("not two random keys")
	}
	r, c := newRecorder(), &clock{start}
	n, _ := newService(t, a, "p", r, c).Get()
	if err := newService(t, a, "p", r, c).Redeem(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if err := newService(t, b, "p", r, c).Redeem(context.Background(), n); !errors.Is(err, nonce.ErrInvalid) {
		t.Fatalf("another process's key opened it: %v", err)
	}
}

// These are nonces for purpose "fuzz" under keysOf("k1"), valid at start. They are constants because each fuzz
// worker runs the setup anew, and a nonce issued there would differ in every one.
const (
	fuzzServiceNonce = "AQJrMf2XjrwKmUIVPESxO9ZrzBdSEKblIAhrYPB4Fg0A4xn5-l5Avz3U-A7rvPuPGsWOYIbIE23jeo3Ijt-OoJXm2PAT19-2"
	fuzzSourceNonce  = "AQJrMbsAfT3OhWAEUlsFIH4dQyNffHdZuXE9LAsXwNFameS8bzcXYzPfyjabPo1xWYk1SMNOxeZCfoR8p4oLUDB7QelPBtNz"
)

func FuzzRedeem(f *testing.F) {
	r := newRecorder()
	c := &clock{start}
	s, err := nonce.New(keysOf("k1"), "fuzz", time.Minute, r.record, nonce.WithClock(c.Now))
	if err != nil {
		f.Fatal(err)
	}
	good := fuzzServiceNonce
	fresh, err := nonce.New(keysOf("k1"), "fuzz", time.Minute, newRecorder().record, nonce.WithClock(c.Now))
	if err != nil {
		f.Fatal(err)
	}
	if err := fresh.Redeem(context.Background(), good); err != nil {
		f.Fatalf("the fixture does not redeem: %v", err)
	}
	f.Add(good)
	f.Add(good + "\n")
	f.Add("")
	f.Add("=")
	f.Add("AQ")
	f.Add("AQAA")
	f.Add(strings.Repeat("A", 200))
	f.Fuzz(func(t *testing.T, candidate string) {
		err := s.Redeem(context.Background(), candidate)
		if candidate == good {
			return
		}
		if !errors.Is(err, nonce.ErrInvalid) {
			t.Fatalf("%q: got %v", candidate, err)
		}
	})
}

func FuzzSourceValid(f *testing.F) {
	c := &clock{start}
	s, err := nonce.NewSource(keysOf("k1"), "fuzz", time.Minute, nonce.WithClock(c.Now))
	if err != nil {
		f.Fatal(err)
	}
	good := fuzzSourceNonce
	if !s.Valid(good) {
		f.Fatal("the fixture is not valid")
	}
	f.Add(good)
	f.Add("")
	f.Add(good[:len(good)-1])
	f.Fuzz(func(t *testing.T, candidate string) {
		if s.Valid(candidate) && candidate != good {
			t.Fatalf("accepted %q", candidate)
		}
	})
}
