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
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func testRingLine(id string, b byte) string {
	return id + " " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) + "\n"
}

func testRing(t *testing.T, lines ...string) *kv.Keyring {
	t.Helper()
	ring, err := kv.ParseKeyring([]byte(strings.Join(lines, "")))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func sealedFixture(t *testing.T) (raw kv.Store, sealed kv.Store) {
	t.Helper()
	raw = kv.NewMemory()
	return raw, kv.NewSealed(raw, testRing(t, testRingLine("k1", 1)), "test")
}

func TestSealed_StoreSeesCiphertextOnly(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	secret := []byte("refresh-token-super-secret")

	if err := sealed.Set(ctx, "a", secret, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := sealed.SetMany(ctx, kv.Entry{Key: "b", Value: secret, TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if set, err := sealed.SetIfAbsent(ctx, "c", secret, time.Minute); err != nil || !set {
		t.Fatalf("SetIfAbsent: set=%v err=%v", set, err)
	}
	for _, key := range []string{"a", "b", "c"} {
		stored, found, err := raw.Get(ctx, key)
		if err != nil || !found {
			t.Fatalf("%s: found=%v err=%v", key, found, err)
		}
		if bytes.Contains(stored, secret) {
			t.Fatalf("%s: the store holds the plaintext", key)
		}
		got, found, err := sealed.Get(ctx, key)
		if err != nil || !found || !bytes.Equal(got, secret) {
			t.Fatalf("%s: round trip: %q found=%v err=%v", key, got, found, err)
		}
	}
	got, found, err := sealed.Take(ctx, "a")
	if err != nil || !found || !bytes.Equal(got, secret) {
		t.Fatalf("Take: %q found=%v err=%v", got, found, err)
	}
	if _, found, _ := raw.Get(ctx, "a"); found {
		t.Fatal("Take left the record in the store")
	}
}

func TestSealed_EveryRecordHasAFreshNonce(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "a", []byte("same"), 0)
	first, _, _ := raw.Get(ctx, "a")
	_ = sealed.Set(ctx, "a", []byte("same"), 0)
	second, _, _ := raw.Get(ctx, "a")
	if bytes.Equal(first, second) {
		t.Fatal("sealing the same value twice produced the same record")
	}
}

func TestSealed_ValueFormatIsVersionKeyIDSaltNonceCiphertext(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "a", []byte("xyz"), 0)
	got, _, _ := raw.Get(ctx, "a")
	want := 1 + 1 + len("k1") + 16 + 12 + len("xyz") + 16
	if len(got) != want || got[0] != 1 || got[1] != 2 || string(got[2:4]) != "k1" {
		t.Fatalf("record %x: want version 1, key ID k1, %d bytes in all", got, want)
	}
}

func TestSealed_RecordMovedToAnotherKeyFails(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "session:a", []byte("a's record"), 0)
	moved, _, _ := raw.Get(ctx, "session:a")
	_ = raw.Set(ctx, "session:b", moved, 0)
	if _, _, err := sealed.Get(ctx, "session:b"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestSealed_RecordOfAnotherPurposeFails(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	ring := testRing(t, testRingLine("k1", 1))
	_ = kv.NewSealed(raw, ring, "sessions").Set(ctx, "a", []byte("x"), 0)
	if _, _, err := kv.NewSealed(raw, ring, "other").Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestSealed_AnyFlippedByteFails(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "a", []byte("record"), 0)
	stored, _, _ := raw.Get(ctx, "a")
	for i := range stored {
		tampered := bytes.Clone(stored)
		tampered[i] ^= 0x01
		_ = raw.Set(ctx, "a", tampered, 0)
		if _, found, err := sealed.Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) || found {
			t.Fatalf("byte %d: found=%v err=%v, want ErrIntegrity", i, found, err)
		}
	}
}

func TestSealed_TruncatedRecordFails(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "a", []byte("record"), 0)
	stored, _, _ := raw.Get(ctx, "a")
	for i := range stored {
		_ = raw.Set(ctx, "a", stored[:i], 0)
		if _, _, err := sealed.Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
			t.Fatalf("%d bytes: got %v, want ErrIntegrity", i, err)
		}
	}
}

func TestSealed_PlaintextRecordFails(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	for _, plain := range []string{`{"id":"s1"}`, `"s1"`, "1", ""} {
		_ = raw.Set(ctx, "a", []byte(plain), 0)
		if _, _, err := sealed.Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
			t.Fatalf("%q: got %v, want ErrIntegrity", plain, err)
		}
	}
}

func TestSealed_UnknownKeyIDFails(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	_ = kv.NewSealed(raw, testRing(t, testRingLine("gone", 1)), "p").Set(ctx, "a", []byte("x"), 0)
	if _, _, err := kv.NewSealed(raw, testRing(t, testRingLine("k1", 2)), "p").Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestSealed_SameIDWithAnotherKeyFails(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	_ = kv.NewSealed(raw, testRing(t, testRingLine("k1", 1)), "p").Set(ctx, "a", []byte("x"), 0)
	if _, _, err := kv.NewSealed(raw, testRing(t, testRingLine("k1", 2)), "p").Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestSealed_TakeOfABadRecordReturnsTheError(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = raw.Set(ctx, "a", []byte("not sealed"), 0)
	if _, found, err := sealed.Take(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) || found {
		t.Fatalf("found=%v err=%v, want ErrIntegrity", found, err)
	}
}

func TestSealed_SetIfAbsentKeepsTheFirstValue(t *testing.T) {
	ctx := context.Background()
	_, sealed := sealedFixture(t)
	if set, err := sealed.SetIfAbsent(ctx, "a", []byte("first"), 0); err != nil || !set {
		t.Fatalf("first: set=%v err=%v", set, err)
	}
	if set, err := sealed.SetIfAbsent(ctx, "a", []byte("second"), 0); err != nil || set {
		t.Fatalf("second: set=%v err=%v", set, err)
	}
	if got, _, _ := sealed.Get(ctx, "a"); string(got) != "first" {
		t.Fatalf("got %q", got)
	}
}

func TestSealed_DeleteKeysCleanupPassThrough(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "ns:revoked-sid", []byte("1"), 0)
	_ = sealed.Set(ctx, "ns:expires", []byte("1"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	keys, err := sealed.Keys(ctx, "ns:")
	if err != nil || len(keys) != 1 || keys[0] != "ns:revoked-sid" {
		t.Fatalf("keys %v, err %v", keys, err)
	}
	if n, err := sealed.Cleanup(ctx); err != nil || n != 1 {
		t.Fatalf("cleanup removed %d, err %v", n, err)
	}
	if err := sealed.Delete(ctx, "ns:revoked-sid"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := raw.Get(ctx, "ns:revoked-sid"); found {
		t.Fatal("Delete did not reach the store")
	}
	if err := sealed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := raw.Get(ctx, "x"); !errors.Is(err, kv.ErrClosed) {
		t.Fatalf("Close did not reach the store: %v", err)
	}
}

func TestSealed_RecordsUnderTheOldKeyOpenAfterRotation(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	_ = kv.NewSealed(raw, testRing(t, testRingLine("old", 1)), "p").Set(ctx, "a", []byte("x"), 0)
	rotated := kv.NewSealed(raw, testRing(t, testRingLine("new", 2), testRingLine("old", 1)), "p")
	if got, found, err := rotated.Get(ctx, "a"); err != nil || !found || string(got) != "x" {
		t.Fatalf("%q found=%v err=%v", got, found, err)
	}
}

func TestSealed_NewRecordsUseTheFirstKey(t *testing.T) {
	ctx := context.Background()
	raw := kv.NewMemory()
	rotated := kv.NewSealed(raw, testRing(t, testRingLine("new", 2), testRingLine("old", 1)), "p")
	_ = rotated.Set(ctx, "a", []byte("x"), 0)
	stored, _, _ := raw.Get(ctx, "a")
	if string(stored[2:2+int(stored[1])]) != "new" {
		t.Fatalf("record sealed under key %q", stored[2:2+int(stored[1])])
	}
	if _, _, err := kv.NewSealed(raw, testRing(t, testRingLine("old", 1)), "p").Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("the old key alone opened a new record: %v", err)
	}
}

// A store outage must stay distinct from tampering: operators alert on ErrIntegrity.
func TestSealed_StoreFailureIsNotAnIntegrityFailure(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = raw.Close()
	for name, call := range map[string]func() error{
		"get":  func() error { _, _, err := sealed.Get(ctx, "a"); return err },
		"take": func() error { _, _, err := sealed.Take(ctx, "a"); return err },
	} {
		if err := call(); !errors.Is(err, kv.ErrClosed) || errors.Is(err, kv.ErrIntegrity) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestParseKeyring_FormatAndCurrentKey(t *testing.T) {
	ring := testRing(t, "# rotated 2026-11\n\n", testRingLine("k2", 2), "  # older\n", testRingLine("k1", 1))
	id, key := ring.Current()
	if id != "k2" || !bytes.Equal(key, bytes.Repeat([]byte{2}, 32)) {
		t.Fatalf("current %q %x", id, key)
	}
	if key, ok := ring.Lookup("k1"); !ok || !bytes.Equal(key, bytes.Repeat([]byte{1}, 32)) {
		t.Fatalf("lookup k1: %x %v", key, ok)
	}
	if _, ok := ring.Lookup("k3"); ok {
		t.Fatal("found a key that is not in the ring")
	}
}

func TestParseKeyring_BareKeyIsASingleKey(t *testing.T) {
	bare := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	ring := testRing(t, bare+"\n")
	id, key := ring.Current()
	if id != kv.BareKeyID || !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("current %q %x", id, key)
	}
}

func TestParseKeyring_Refuses(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	long := base64.StdEncoding.EncodeToString(make([]byte, 33))
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for name, in := range map[string]string{
		"empty":             "",
		"only comments":     "# nothing\n\n",
		"short key":         "k1 " + short + "\n",
		"long key":          "k1 " + long + "\n",
		"short bare key":    short + "\n",
		"not base64":        "k1 " + strings.Repeat("!", 44) + "\n",
		"duplicate id":      "k1 " + good + "\nk1 " + good + "\n",
		"bare and named":    good + "\nk1 " + good + "\n",
		"two bare":          good + "\n" + good + "\n",
		"three fields":      "k1 " + good + " extra\n",
		"id with bad chars": "k/1 " + good + "\n",
		"id too long":       strings.Repeat("k", 65) + " " + good + "\n",
		"oversized file":    strings.Repeat("#", 1<<20),
	} {
		if _, err := kv.ParseKeyring([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Keys reach logs through errors and the formatted ring far more easily than through code that means to.
func TestKeyring_KeyMaterialStaysOutOfErrorsAndFormatting(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 31))
	if _, err := kv.ParseKeyring([]byte("k1 " + secret + "\n")); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error carries the key: %v", err)
	}
	line := testRingLine("k1", 9)
	encoded := strings.Fields(line)[1]
	ring := testRing(t, line)
	for _, out := range []string{fmt.Sprintf("%v", ring), fmt.Sprintf("%+v", ring), fmt.Sprintf("%#v", ring), ring.String()} {
		if strings.Contains(out, encoded) || strings.Contains(out, "9, 9") || strings.Contains(out, "0909") {
			t.Fatalf("formatted ring shows the key: %s", out)
		}
	}
}

func TestKeyring_ReturnedKeyIsACopy(t *testing.T) {
	ring := testRing(t, testRingLine("k1", 1))
	_, key := ring.Current()
	clear(key)
	if _, again := ring.Current(); !bytes.Equal(again, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("clearing a returned key changed the ring")
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func writeRing(t *testing.T, path, content string, modTime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}

func loadedRing(t *testing.T, content string) (ring *kv.Keyring, path string, clock *fakeClock) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "store.key")
	writeRing(t, path, content, time.Unix(1000, 0))
	ring, err := kv.LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	clock = &fakeClock{now: time.Unix(5000, 0)}
	kv.SetKeyringClock(ring, clock.Now)
	return ring, path, clock
}

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestKeyring_AReloadOfTheFileTakesEffect(t *testing.T) {
	ring, path, clock := loadedRing(t, testRingLine("k1", 1))
	writeRing(t, path, testRingLine("k2", 2)+testRingLine("k1", 1), time.Unix(2000, 0))

	clock.Advance(31 * time.Second)
	if id, _ := ring.Current(); id != "k2" {
		t.Fatalf("current %q, want k2", id)
	}
	if _, ok := ring.Lookup("k1"); !ok {
		t.Fatal("k1 lost")
	}
}

func TestKeyring_FileIsCheckedAtMostEvery30Seconds(t *testing.T) {
	ring, path, clock := loadedRing(t, testRingLine("k1", 1))
	if id, _ := ring.Current(); id != "k1" {
		t.Fatalf("current %q", id)
	}
	writeRing(t, path, testRingLine("k2", 2), time.Unix(2000, 0))
	clock.Advance(29 * time.Second)
	if id, _ := ring.Current(); id != "k1" {
		t.Fatalf("checked within the 30 s: current %q", id)
	}
	clock.Advance(2 * time.Second)
	if id, _ := ring.Current(); id != "k2" {
		t.Fatalf("not checked after 30 s: current %q", id)
	}
}

func TestKeyring_AnUnchangedFileIsNotParsedAgain(t *testing.T) {
	ring, path, clock := loadedRing(t, testRingLine("k1", 1))
	// Same mtime and size with other content: only a re-read could see it.
	writeRing(t, path, testRingLine("k2", 2), time.Unix(1000, 0))
	clock.Advance(time.Minute)
	if id, _ := ring.Current(); id != "k1" {
		t.Fatalf("re-read an unchanged file: current %q", id)
	}
}

func TestKeyring_ABrokenReloadKeepsTheOldKeysAndLogsAnError(t *testing.T) {
	ring, path, clock := loadedRing(t, testRingLine("k1", 1))
	logs := captureSlog(t)
	writeRing(t, path, "k1 not-a-key\n", time.Unix(2000, 0))

	clock.Advance(31 * time.Second)
	id, key := ring.Current()
	if id != "k1" || !bytes.Equal(key, bytes.Repeat([]byte{1}, 32)) {
		t.Fatalf("current %q %x", id, key)
	}
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("no error logged: %q", logs)
	}
	if strings.Contains(logs.String(), "not-a-key") {
		t.Fatalf("the log carries the file's content: %q", logs)
	}

	writeRing(t, path, testRingLine("k2", 2), time.Unix(2000, 0))
	clock.Advance(31 * time.Second)
	if id, _ := ring.Current(); id != "k2" {
		t.Fatalf("a repaired file with the broken one's mtime stays ignored: current %q", id)
	}
}

func TestKeyring_AMissingFileKeepsTheOldKeysAndLogsAnError(t *testing.T) {
	ring, path, clock := loadedRing(t, testRingLine("k1", 1))
	logs := captureSlog(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clock.Advance(31 * time.Second)
	if id, _ := ring.Current(); id != "k1" {
		t.Fatalf("current %q", id)
	}
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("no error logged: %q", logs)
	}
}

func TestLoadKeyring_RefusesABrokenFileAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.key")
	if _, err := kv.LoadKeyring(path); err == nil {
		t.Fatal("accepted a missing file")
	}
	writeRing(t, path, "", time.Unix(1000, 0))
	if _, err := kv.LoadKeyring(path); err == nil {
		t.Fatal("accepted an empty file")
	}
}

func TestKeyring_ConcurrentUseDuringReload(t *testing.T) {
	ring, path, clock := loadedRing(t, testRingLine("k1", 1))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				id, key := ring.Current()
				if len(key) != 32 || id == "" {
					t.Error("torn read of the ring")
					return
				}
			}
		})
	}
	for i := range 20 {
		writeRing(t, path, testRingLine("k2", 2), time.Unix(int64(2000+i), 0))
		clock.Advance(31 * time.Second)
	}
	wg.Wait()
}

func TestMemory_SetIfAbsent_ConcurrencyHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	s := kv.NewMemory()
	for i := range 200 {
		key := fmt.Sprintf("once:%d", i)
		var wins atomic.Int64
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if set, err := s.SetIfAbsent(ctx, key, []byte("1"), time.Minute); err == nil && set {
					wins.Add(1)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%s: %d winners", key, wins.Load())
		}
	}
}

func TestMemory_SetIfAbsent_ExpiredCountsAsAbsent(t *testing.T) {
	ctx := context.Background()
	s := kv.NewMemory()
	if set, _ := s.SetIfAbsent(ctx, "a", []byte("old"), 5*time.Millisecond); !set {
		t.Fatal("first write refused")
	}
	if set, _ := s.SetIfAbsent(ctx, "a", []byte("new"), time.Minute); set {
		t.Fatal("overwrote a live record")
	}
	time.Sleep(10 * time.Millisecond)
	if set, _ := s.SetIfAbsent(ctx, "a", []byte("new"), time.Minute); !set {
		t.Fatal("an expired record counted as present")
	}
	if got, _, _ := s.Get(ctx, "a"); string(got) != "new" {
		t.Fatalf("got %q", got)
	}
}

func TestMemory_SetIfAbsent_ClosedStoreFails(t *testing.T) {
	s := kv.NewMemory()
	_ = s.Close()
	if _, err := s.SetIfAbsent(context.Background(), "a", nil, 0); !errors.Is(err, kv.ErrClosed) {
		t.Fatalf("got %v", err)
	}
}

type countingStore struct {
	kv.Store
	calls atomic.Int64
	err   error
}

func (s *countingStore) Cleanup(context.Context) (int, error) {
	s.calls.Add(1)
	return 0, s.err
}

func TestReap_RunsCleanupUntilTheContextEnds(t *testing.T) {
	store := &countingStore{Store: kv.NewMemory()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { kv.Reap(ctx, store, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for store.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("Cleanup is not being called")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reap did not end with its context")
	}
}

func TestReap_LogsAFailureAndKeepsGoing(t *testing.T) {
	var buf safeBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	store := &countingStore{Store: kv.NewMemory(), err: errors.New("database down")}
	go kv.Reap(t.Context(), store, time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for store.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("Reap stopped after a failure")
		}
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(buf.String(), "database down") {
		t.Fatalf("failure not logged: %q", buf.String())
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestReplayCache_SecondSightingIsSeen(t *testing.T) {
	cache := kv.NewReplayCache(kv.NewMemory())
	until := time.Now().Add(time.Minute)
	if seen, err := cache.Seen("proof", until); err != nil || seen {
		t.Fatalf("first: seen=%v err=%v", seen, err)
	}
	if seen, err := cache.Seen("proof", until); err != nil || !seen {
		t.Fatalf("second: seen=%v err=%v", seen, err)
	}
	if seen, err := cache.Seen("other", until); err != nil || seen {
		t.Fatalf("other id: seen=%v err=%v", seen, err)
	}
}

func TestReplayCache_ReplicasOnOneStoreShareIt(t *testing.T) {
	store := kv.NewMemory()
	until := time.Now().Add(time.Minute)
	if seen, err := kv.NewReplayCache(store).Seen("proof", until); err != nil || seen {
		t.Fatalf("first: seen=%v err=%v", seen, err)
	}
	if seen, err := kv.NewReplayCache(store).Seen("proof", until); err != nil || !seen {
		t.Fatalf("at the other replica: seen=%v err=%v", seen, err)
	}
}

func TestReplayCache_StoreFailureIsAnError(t *testing.T) {
	store := kv.NewMemory()
	_ = store.Close()
	if _, err := kv.NewReplayCache(store).Seen("proof", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("no error from a store that cannot answer")
	}
}

func TestReplayCache_KeyIsAHashOfTheID(t *testing.T) {
	ctx := context.Background()
	store := kv.NewMemory()
	_, _ = kv.NewReplayCache(store).Seen("proof-id", time.Now().Add(time.Minute))
	keys, err := store.Keys(ctx, "")
	if err != nil || len(keys) != 1 || strings.Contains(keys[0], "proof-id") {
		t.Fatalf("keys %v, err %v", keys, err)
	}
}

// An until already past must still leave a record with an expiry: a zero TTL means none,
// and such a row would never be reaped.
func TestReplayCache_PastUntilStillExpires(t *testing.T) {
	store := &ttlRecorder{Store: kv.NewMemory()}
	if _, err := kv.NewReplayCache(store).Seen("proof", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if store.ttl <= 0 {
		t.Fatalf("ttl %v", store.ttl)
	}
}

type ttlRecorder struct {
	kv.Store
	ttl time.Duration
}

func (s *ttlRecorder) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	s.ttl = ttl
	return s.Store.SetIfAbsent(ctx, key, value, ttl)
}

// Every record has a key of its own, so writes cannot run up against the limit of random GCM nonces under one key.
func TestSealed_RecordsOfTheSameValueShareNoSalt(t *testing.T) {
	ctx := context.Background()
	raw, sealed := sealedFixture(t)
	_ = sealed.Set(ctx, "a", []byte("xyz"), 0)
	_ = sealed.Set(ctx, "b", []byte("xyz"), 0)
	first, _, _ := raw.Get(ctx, "a")
	second, _, _ := raw.Get(ctx, "b")
	if string(first[4:20]) == string(second[4:20]) {
		t.Fatal("two records share a salt")
	}
}
