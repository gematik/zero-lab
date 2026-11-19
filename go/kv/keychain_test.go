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
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

const purpose = "test records"

// counting is a key service that counts what it is asked to unwrap.
type counting struct {
	kv.LocalKEK
	calls int
	fail  error
}

func (c *counting) Unwrap(ctx context.Context, kekID string, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	c.calls++
	if c.fail != nil {
		return nil, c.fail
	}
	return c.LocalKEK.Unwrap(ctx, kekID, iv, ciphertext, tag, aad)
}

func newKEK(t *testing.T) kv.LocalKEK {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	return kek
}

// entry is one more entry for a keychain file: when it is in force, and whether it brings a name key.
type entry struct {
	activeFrom time.Time
	names      bool
}

// extend returns the file with the entries added, each the next version.
func extend(t *testing.T, kek kv.LocalKEK, file []byte, entries ...entry) []byte {
	t.Helper()
	for _, e := range entries {
		var err error
		if file, err = kek.Extend(file, purpose, "zeta-test-db-kek-v1", e.activeFrom, e.names); err != nil {
			t.Fatal(err)
		}
	}
	return file
}

func nameIDs(chain *kv.Keychain) string {
	var ids []string
	for _, name := range chain.NameKeys() {
		ids = append(ids, name.ID)
	}
	return strings.Join(ids, " ")
}

// Server rule 19: the keys of a keychain are wrapped under a key the key service holds. The newest entry
// whose time has come seals and every entry opens. An entry brings a name key only when the names are to
// change: the name key in force is that of the newest such entry at or below the one that seals.
func TestKeychainCurrentIsTheNewestActiveEntry(t *testing.T) {
	kek := newKEK(t)
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	file := extend(t, kek, nil,
		entry{start.Add(-time.Hour), false}, // the first entry has a name key whatever is asked
		entry{start.Add(time.Hour), false},
		entry{start.Add(48 * time.Hour), true},
	)
	now := start
	chain, err := kv.ParseKeychain(context.Background(), file, purpose, kek, kv.WithKeychainClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		at             time.Time
		current, names string
	}{
		{start, "v1", "v1 v3"},
		// A new key for sealing leaves the names as they are.
		{start.Add(time.Hour), "v2", "v1 v3"},
		{start.Add(72 * time.Hour), "v3", "v3 v1"},
		// Before its first entry is in force a keychain seals nothing.
		{start.Add(-24 * time.Hour), "", "v3 v1"},
	} {
		now = step.at
		id, key := chain.Current()
		if id != step.current || (len(key) != 32) != (id == "") {
			t.Errorf("at %s: current %q with %d bytes, want %q", step.at, id, len(key), step.current)
		}
		if got := nameIDs(chain); got != step.names {
			t.Errorf("at %s: name keys of %s, want %s", step.at, got, step.names)
		}
	}
	seen := map[string]bool{}
	for _, id := range []string{"v1", "v2", "v3"} {
		key, ok := chain.Lookup(id)
		if !ok || len(key) != 32 || seen[string(key)] {
			t.Errorf("%s: found %v, %d bytes, or the key of another entry", id, ok, len(key))
		}
		seen[string(key)] = true
	}
	for _, name := range chain.NameKeys() {
		if len(name.Key) != 32 || seen[string(name.Key)] {
			t.Errorf("%s: the name key has %d bytes or is another key", name.ID, len(name.Key))
		}
		seen[string(name.Key)] = true
	}
	if _, ok := chain.Lookup("v4"); ok {
		t.Error("found an entry the keychain does not have")
	}
	entries := chain.Entries()
	if len(entries) != 3 || entries[1].ID != "v2" || entries[1].Version != 2 || strings.Join(entries[1].Keys, " ") != "seal" || strings.Join(entries[2].Keys, " ") != "name seal" {
		t.Errorf("entries: %+v", entries)
	}
	if s := chain.String(); !strings.Contains(s, "entries: 3") || len(s) > 100 {
		t.Errorf("String() = %s", s)
	}
}

// Everything a file says of an entry is bound into the wrapping of its keys, and so is what the file is
// for: changed, moved or under another key, an entry is not unwrapped, and nothing of the file is taken.
func TestKeychainRefusals(t *testing.T) {
	kek := newKEK(t)
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	file := string(extend(t, kek, nil, entry{at, true}, entry{at.Add(time.Hour), false}))
	change := func(from, to string) []byte {
		t.Helper()
		if strings.Count(file, from) != 1 {
			t.Fatalf("the file has %q %d times", from, strings.Count(file, from))
		}
		return []byte(strings.Replace(file, from, to, 1))
	}
	// The file without its first entry, which is the one with the name key.
	head, rest, _ := strings.Cut(file, `"entries": [`)
	_, second, _ := strings.Cut(rest, `    },`)
	onlyLater := []byte(head + `"entries": [` + second)
	for name, data := range map[string][]byte{
		"no JSON":                        []byte("v1 AAAA"),
		"no entry":                       []byte(`{"purpose":"test records","entries":[]}`),
		"an unknown member":              change(`"purpose"`, `"note": "x", "purpose"`),
		"a file for something else":      change(`"purpose": "test records"`, `"purpose": "other records"`),
		"an entry given another time":    change(`"activeFrom": "2026-11-18T13:00:00Z"`, `"activeFrom": "2027-11-18T13:00:00Z"`),
		"an entry given another version": change(`"version": 2`, `"version": 7`),
		"an entry given another id":      change(`"id": "v2"`, `"id": "v9"`),
		"an entry given another kekId": change(`"kekId": "zeta-test-db-kek-v1",
      "keys": [
        "seal"`, `"kekId": "another",
      "keys": [
        "seal"`),
		"an entry said to hold a key more": change(`"keys": [
        "seal"`, `"keys": [
        "name",
        "seal"`),
		"an entry that is there and revoked": change(`"purpose"`, `"revoked": ["v1"], "purpose"`),
		"no entry with a name key":           onlyLater,
		"wrapped under another key":          extend(t, newKEK(t), nil, entry{at, true}),
	} {
		if chain, err := kv.ParseKeychain(context.Background(), data, purpose, kek); err == nil {
			t.Errorf("%s: taken as %v", name, chain)
		}
	}
	if _, err := kv.ParseKeychain(context.Background(), []byte(file), "other records", kek); err == nil {
		t.Error("a keychain was taken for another purpose than its own")
	}
	away := &counting{LocalKEK: kek, fail: errors.New("the key service is away")}
	if _, err := kv.ParseKeychain(context.Background(), []byte(file), purpose, away); err == nil || !strings.Contains(err.Error(), "the key service is away") {
		t.Errorf("without the key service: %v", err)
	}
}

// Server rules 8 and 22: a keychain is read once, at start. A changed file changes nothing in the process
// that read it and asks the key service nothing; a keychain loaded from the changed file, as a rollout
// starts one, has the new entry in force at its time, opens what the old entry sealed, and loses only what a
// revoked entry sealed.
func TestKeychainReadsItsFileOnceAtStart(t *testing.T) {
	kek := &counting{LocalKEK: newKEK(t)}
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "keychain.json")
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	one := extend(t, kek.LocalKEK, nil, entry{start.Add(-time.Hour), true})
	write(one)
	now := start
	clock := kv.WithKeychainClock(func() time.Time { return now })
	ctx := context.Background()
	chain, err := kv.LoadKeychain(ctx, path, purpose, kek, clock)
	if err != nil {
		t.Fatal(err)
	}
	records := kv.NewMemory()
	store := kv.NewSealed(records, chain, "test records")
	if err := store.Set(ctx, "a", []byte("sealed under v1"), time.Hour); err != nil {
		t.Fatal(err)
	}

	two := extend(t, kek.LocalKEK, one, entry{start.Add(2 * time.Hour), false})
	write(two)
	now = start.Add(3 * time.Hour)
	if id, _ := chain.Current(); id != "v1" || kek.calls != 1 || len(chain.Entries()) != 1 {
		t.Fatalf("the changed file was taken: current %q, %d entries, %d calls to the key service", id, len(chain.Entries()), kek.calls)
	}
	write([]byte("{"))
	if id, _ := chain.Current(); id != "v1" {
		t.Fatalf("with a broken file: current %q", id)
	}

	write(two)
	next, err := kv.LoadKeychain(ctx, path, purpose, kek, clock)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := next.Current(); id != "v2" {
		t.Fatalf("a keychain loaded after the change: current %q", id)
	}
	nextStore := kv.NewSealed(records, next, "test records")
	if got, found, err := nextStore.Get(ctx, "a"); err != nil || !found || string(got) != "sealed under v1" {
		t.Fatalf("a: %q, found %v, %v", got, found, err)
	}
	if err := nextStore.Set(ctx, "b", []byte("sealed under v2"), time.Hour); err != nil {
		t.Fatal(err)
	}

	write([]byte(strings.Replace(string(two), `"purpose"`, `"revoked": ["v1"], "purpose"`, 1)))
	if _, err := kv.LoadKeychain(ctx, path, purpose, kek, clock); err == nil {
		t.Fatal("a file that revokes an entry it still holds was taken")
	}
	withoutFirst := []byte(strings.Replace(string(two), string(two)[strings.Index(string(two), `    {
      "id": "v1"`):strings.Index(string(two), `    {
      "id": "v2"`)], "", 1))
	// v2 alone has no name key, so the file is given one by a third entry.
	withoutFirst = extend(t, kek.LocalKEK, withoutFirst, entry{now.Add(time.Hour), true})
	write([]byte(strings.Replace(string(withoutFirst), `"purpose"`, `"revoked": ["v1"], "purpose"`, 1)))
	third, err := kv.LoadKeychain(ctx, path, purpose, kek, clock)
	if err != nil {
		t.Fatal(err)
	}
	if revoked := third.Revoked(); len(revoked) != 1 || revoked[0] != "v1" {
		t.Errorf("revoked: %v", revoked)
	}
	thirdStore := kv.NewSealed(records, third, "test records")
	if _, _, err := thirdStore.Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Errorf("a record of a revoked entry: %v", err)
	}
	if got, found, err := thirdStore.Get(ctx, "b"); err != nil || !found || string(got) != "sealed under v2" {
		t.Errorf("b: %q, found %v, %v", got, found, err)
	}
}

// Server rule 22: a record that outlives a key is sealed again under the current one, with the value and
// the expiry it had, so that the old key can go. The store below finds such records by their marks, and
// says by which keys records are still sealed.
func TestResealTakesARecordToTheCurrentKey(t *testing.T) {
	kek := newKEK(t)
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	now := start
	chain, err := kv.ParseKeychain(context.Background(), extend(t, kek, nil, entry{start.Add(-time.Hour), true}, entry{start.Add(time.Hour), false}),
		purpose, kek, kv.WithKeychainClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	// The class of a record is the version of what it holds. A later release writes another one: here that
	// of what is written now is asked for the prefix, and what is stored keeps the class it was written in.
	version := "0"
	class := func(key string) string {
		if key == "" {
			return version
		}
		return "0"
	}
	inner := kv.NewMemory(kv.WithMemoryClock(func() time.Time { return now }), kv.WithMemoryMark(kv.SealedMarker(class)))
	store := kv.NewSealed(inner, chain, "test records", kv.WithSealedExpiry(func() time.Time { return now }), kv.WithSealedClass(class))
	resealer := store.(kv.Resealer)
	ctx := context.Background()
	others := func() string {
		t.Helper()
		keys, err := resealer.Others(ctx, "", "", 10)
		n, errCount := resealer.CountOthers(ctx, "")
		if err != nil || errCount != nil || n != len(keys) {
			t.Fatalf("others: %v, counted %d, %v, %v", keys, n, err, errCount)
		}
		return strings.Join(keys, " ")
	}
	sealedBy := func() map[string]int {
		t.Helper()
		by, err := resealer.SealedByKeys(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		return by
	}
	if err := store.Set(ctx, "a", []byte("lives a year"), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, "forever", []byte("never ends"), 0); err != nil {
		t.Fatal(err)
	}
	if resealed, err := resealer.Reseal(ctx, "a"); err != nil || resealed || others() != "" {
		t.Fatalf("under the current key: resealed %v, others %q, %v", resealed, others(), err)
	}

	now = start.Add(2 * time.Hour)
	if got := others(); got != "a forever" {
		t.Errorf("sealed by another key, after the change: %s", got)
	}
	if by := sealedBy(); len(by) != 1 || by["v1"] != 2 {
		t.Errorf("sealed by: %v", by)
	}
	if mark := resealer.Mark(""); mark != "2:v2:0" {
		t.Errorf("the mark of what is written now: %q", mark)
	}
	for _, key := range []string{"a", "forever"} {
		if id, found, err := resealer.SealedBy(ctx, key); err != nil || !found || id != "v1" {
			t.Fatalf("%s before: sealed by %q, found %v, %v", key, id, found, err)
		}
		if resealed, err := resealer.Reseal(ctx, key); err != nil || !resealed {
			t.Fatalf("%s: resealed %v, %v", key, resealed, err)
		}
		if resealed, err := resealer.Reseal(ctx, key); err != nil || resealed {
			t.Errorf("%s again: resealed %v, %v", key, resealed, err)
		}
	}
	if by := sealedBy(); len(by) != 1 || by["v2"] != 2 || others() != "" {
		t.Errorf("after resealing: sealed by %v, others %q", by, others())
	}
	if got, found, err := store.Get(ctx, "a"); err != nil || !found || string(got) != "lives a year" {
		t.Errorf("a: %q, found %v, %v", got, found, err)
	}
	if resealed, err := resealer.Reseal(ctx, "nothing"); err != nil || resealed {
		t.Errorf("no record: resealed %v, %v", resealed, err)
	}

	// A release that writes another version of what the records hold finds those of the version before.
	version = "1"
	if got := others(); got != "a forever" {
		t.Errorf("of the version before: %s", got)
	}
	version = "0"

	// A record moves to another key with what it had, once; what is there already stays.
	if moved, err := resealer.Rename(ctx, "a", "b"); err != nil || !moved {
		t.Fatalf("rename: moved %v, %v", moved, err)
	}
	if _, found, _ := store.Get(ctx, "a"); found {
		t.Error("the record is still under its old key")
	}
	if err := store.Set(ctx, "a", []byte("an older copy"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if moved, err := resealer.Rename(ctx, "a", "b"); err != nil || !moved {
		t.Errorf("rename onto a record: moved %v, %v", moved, err)
	}
	if got, _, _ := store.Get(ctx, "b"); string(got) != "lives a year" {
		t.Errorf("a record was overwritten by an older one: %q", got)
	}
	if moved, err := resealer.Rename(ctx, "a", "c"); err != nil || moved {
		t.Errorf("rename of nothing: moved %v, %v", moved, err)
	}
	// It ends when it would have: a year after it was written, not after it was sealed again.
	now = start.Add(365*24*time.Hour + time.Minute)
	if _, found, _ := store.Get(ctx, "b"); found {
		t.Error("the record outlived its time")
	}
	if got, found, _ := store.Get(ctx, "forever"); !found || string(got) != "never ends" {
		t.Errorf("forever: %q, found %v", got, found)
	}
}

// Server rule 22: with an agreement, an entry whose time has come waits until the replicas are all ready for
// it, and says itself what it is ready for.
func TestKeychainEntryWaitsForTheOtherReplicas(t *testing.T) {
	kek := newKEK(t)
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	now := start
	agreed := map[string]bool{"v1": true}
	chain, err := kv.ParseKeychain(context.Background(), extend(t, kek, nil, entry{start.Add(-time.Hour), true}, entry{start.Add(time.Hour), true}),
		purpose, kek, kv.WithKeychainClock(func() time.Time { return now }), kv.WithKeychainAgreement(func(id string) bool { return agreed[id] }))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(chain.Ready(), " "); got != "v1" {
		t.Errorf("ready before the time: %s", got)
	}
	now = start.Add(2 * time.Hour)
	if got := strings.Join(chain.Ready(), " "); got != "v1 v2" {
		t.Errorf("ready after the time: %s", got)
	}
	if id, _ := chain.Current(); id != "v1" || nameIDs(chain) != "v1 v2" {
		t.Errorf("before the others are ready: current %q, name keys of %s", id, nameIDs(chain))
	}
	if names := chain.NameKeys(); !names[0].Since.Equal(start.Add(-time.Hour)) {
		t.Errorf("the name key in force is since %s", names[0].Since)
	}
	agreed["v2"] = true
	if id, _ := chain.Current(); id != "v2" || nameIDs(chain) != "v2 v1" {
		t.Errorf("once all are ready: current %q, name keys of %s", id, nameIDs(chain))
	}
	agreed = map[string]bool{}
	if id, key := chain.Current(); id != "" || key != nil {
		t.Errorf("with nothing agreed: current %q", id)
	}
}
