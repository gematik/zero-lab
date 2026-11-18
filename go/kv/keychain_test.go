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
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

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

func entry(t *testing.T, kek kv.LocalKEK, id string, activeFrom time.Time) string {
	t.Helper()
	e, err := kek.NewEntry(id, "zeta-test-db-kek-v1", activeFrom)
	if err != nil {
		t.Fatal(err)
	}
	return string(e)
}

func keychainOf(entries ...string) []byte { return []byte("[" + strings.Join(entries, ",") + "]") }

// Server rule 19: the keys of a keychain are wrapped under a key the key service holds. The newest entry
// whose time has come seals, every entry opens, and the name keys come current first.
func TestKeychainCurrentIsTheNewestActiveEntry(t *testing.T) {
	kek := newKEK(t)
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	data := keychainOf(
		entry(t, kek, "records-v2", start.Add(time.Hour)),
		entry(t, kek, "records-v1", start.Add(-time.Hour)),
		entry(t, kek, "records-v3", start.Add(48*time.Hour)),
	)
	now := start
	chain, err := kv.ParseKeychain(context.Background(), data, kek, kv.WithKeychainClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	ids := func() (ids []string) {
		for _, name := range chain.NameKeys() {
			ids = append(ids, name.ID)
		}
		return ids
	}
	for _, step := range []struct {
		at      time.Time
		current string
		names   string
	}{
		{start, "records-v1", "records-v1 records-v3 records-v2"},
		{start.Add(time.Hour), "records-v2", "records-v2 records-v3 records-v1"},
		{start.Add(72 * time.Hour), "records-v3", "records-v3 records-v2 records-v1"},
		// Before its first entry is active a keychain seals nothing: other keys do until then.
		{start.Add(-24 * time.Hour), "", "records-v3 records-v2 records-v1"},
	} {
		now = step.at
		id, key := chain.Current()
		if id != step.current || (len(key) != 32) != (id == "") {
			t.Errorf("at %s: current %q with %d bytes, want %q", step.at, id, len(key), step.current)
		}
		if got := strings.Join(ids(), " "); got != step.names {
			t.Errorf("at %s: name keys of %s, want %s", step.at, got, step.names)
		}
	}
	seen := map[string]bool{}
	for _, id := range []string{"records-v1", "records-v2", "records-v3"} {
		key, ok := chain.Lookup(id)
		if !ok || len(key) != 32 || seen[string(key)] {
			t.Errorf("%s: found %v, %d bytes, or the key of another entry", id, ok, len(key))
		}
		seen[string(key)] = true
	}
	for _, name := range chain.NameKeys() {
		if len(name.Key) != 32 || seen[string(name.Key)] {
			t.Errorf("%s: the name key has %d bytes or is a sealing key", name.ID, len(name.Key))
		}
		seen[string(name.Key)] = true
	}
	if _, ok := chain.Lookup("records-v4"); ok {
		t.Error("found an entry the keychain does not have")
	}
	if s := chain.String(); !strings.Contains(s, "entries: 3") || len(s) > 80 {
		t.Errorf("String() = %s", s)
	}
}

// What a keychain file may not be: nothing of it is taken then.
func TestKeychainRefusals(t *testing.T) {
	kek := newKEK(t)
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	v1 := entry(t, kek, "records-v1", at)
	for name, data := range map[string][]byte{
		"no JSON":                          []byte("records-v1 AAAA"),
		"no entry":                         []byte("[]"),
		"an unknown member":                []byte(strings.Replace(v1, `"id"`, `"note":"x","id"`, 1)),
		"an ID without a version":          keychainOf(strings.ReplaceAll(v1, "records-v1", "records")),
		"another ID than was wrapped":      keychainOf(strings.ReplaceAll(v1, "records-v1", "records-v7")),
		"marked as emergency afterwards":   keychainOf(strings.Replace(v1, `"id"`, `"emergency":true,"id"`, 1)),
		"keys that are no base64":          keychainOf(strings.Replace(v1, `"keys":"`, `"keys":"%`, 1)),
		"no kekId":                         keychainOf(strings.Replace(v1, `"kekId":"zeta-test-db-kek-v1"`, `"kekId":""`, 1)),
		"a version twice":                  keychainOf(v1, entry(t, kek, "other-v1", at.Add(time.Hour))),
		"a version active before the last": keychainOf(v1, entry(t, kek, "records-v2", at.Add(-time.Hour))),
		"wrapped under another key":        keychainOf(entry(t, newKEK(t), "records-v1", at)),
	} {
		if chain, err := kv.ParseKeychain(context.Background(), data, kek); err == nil {
			t.Errorf("%s: taken as %v", name, chain)
		}
	}
	away := &counting{LocalKEK: kek, fail: errors.New("the key service is away")}
	if _, err := kv.ParseKeychain(context.Background(), keychainOf(v1), away); err == nil || !strings.Contains(err.Error(), "the key service is away") {
		t.Errorf("without the key service: %v", err)
	}
}

// Server rules 6 and 22: a keychain follows its file without a restart, asks the key service only for
// entries it does not have yet, keeps its keys when the file is broken or the key service is away, and
// seals with a new entry from the time that entry names.
func TestKeychainFollowsItsFile(t *testing.T) {
	kek := &counting{LocalKEK: newKEK(t)}
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "keychain.json")
	v1 := entry(t, kek.LocalKEK, "records-v1", start.Add(-time.Hour))
	write := func(data []byte, mod time.Time) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	write(keychainOf(v1), start)
	now := start
	chain, err := kv.LoadKeychain(context.Background(), path, kek, kv.WithKeychainClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	store := kv.NewSealed(kv.NewMemory(), chain, "test records")
	ctx := context.Background()
	if err := store.Set(ctx, "a", []byte("sealed under v1"), time.Hour); err != nil {
		t.Fatal(err)
	}

	v2 := entry(t, kek.LocalKEK, "records-v2", start.Add(2*time.Hour))
	now = start.Add(time.Minute)
	write(keychainOf(v1, v2), now)
	if id, _ := chain.Current(); id != "records-v1" || kek.calls != 2 {
		t.Fatalf("after adding an entry for later: current %q, %d calls to the key service, want records-v1 and 2", id, kek.calls)
	}
	now = start.Add(3 * time.Hour)
	if id, _ := chain.Current(); id != "records-v2" {
		t.Fatalf("after its time: current %q", id)
	}
	if err := store.Set(ctx, "b", []byte("sealed under v2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"a": "sealed under v1", "b": "sealed under v2"} {
		if got, found, err := store.Get(ctx, key); err != nil || !found || string(got) != want {
			t.Errorf("%s: %q, found %v, %v", key, got, found, err)
		}
	}

	// A broken file and an absent key service change nothing.
	now = now.Add(time.Minute)
	write([]byte("{"), now)
	if id, _ := chain.Current(); id != "records-v2" {
		t.Errorf("with a broken file: current %q", id)
	}
	kek.fail = errors.New("the key service is away")
	now = now.Add(time.Minute)
	write(keychainOf(v1, v2, entry(t, kek.LocalKEK, "records-v3", now)), now)
	if id, _ := chain.Current(); id != "records-v2" {
		t.Errorf("without the key service: current %q", id)
	}
	kek.fail = nil

	// Without the old entry its records are gone, and no other.
	now = now.Add(time.Minute)
	write(keychainOf(v2), now)
	chain.Current()
	if _, _, err := store.Get(ctx, "a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Errorf("a record of a dropped entry: %v", err)
	}
	if got, found, err := store.Get(ctx, "b"); err != nil || !found || !bytes.Equal(got, []byte("sealed under v2")) {
		t.Errorf("b: %q, found %v, %v", got, found, err)
	}
}

// Server rule 22: a record that outlives a key is sealed again under the current one, with the value and
// the expiry it had, so that the old key can go. A record the current key sealed is left alone.
func TestResealTakesARecordToTheCurrentKey(t *testing.T) {
	kek := newKEK(t)
	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	now := start
	chain, err := kv.ParseKeychain(context.Background(), keychainOf(
		entry(t, kek, "records-v1", start.Add(-time.Hour)), entry(t, kek, "records-v2", start.Add(time.Hour)),
	), kek, kv.WithKeychainClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	// The class of a record is the version of what it holds, which a later release raises for some keys.
	version := map[string]string{"": "0", "a": "0", "forever": "0", "nothing": "0", "b": "0", "c": "0"}
	class := func(key string) string { return version[key] }
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
	if err := store.Set(ctx, "a", []byte("lives a year"), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, "forever", []byte("never ends"), 0); err != nil {
		t.Fatal(err)
	}
	if resealed, err := resealer.Reseal(ctx, "a"); err != nil || resealed {
		t.Fatalf("under the current key: resealed %v, %v", resealed, err)
	}

	if got := others(); got != "" {
		t.Errorf("sealed by another key, before the change: %s", got)
	}
	now = start.Add(2 * time.Hour)
	// The store finds what the key of before sealed without reading it.
	if got := others(); got != "a forever" {
		t.Errorf("sealed by another key, after the change: %s", got)
	}
	for _, key := range []string{"a", "forever"} {
		if id, found, err := resealer.SealedBy(ctx, key); err != nil || !found || id != "records-v1" {
			t.Fatalf("%s before: sealed by %q, found %v, %v", key, id, found, err)
		}
		if resealed, err := resealer.Reseal(ctx, key); err != nil || !resealed {
			t.Fatalf("%s: resealed %v, %v", key, resealed, err)
		}
		if id, _, _ := resealer.SealedBy(ctx, key); id != "records-v2" {
			t.Errorf("%s after: sealed by %q", key, id)
		}
		if resealed, err := resealer.Reseal(ctx, key); err != nil || resealed {
			t.Errorf("%s again: resealed %v, %v", key, resealed, err)
		}
	}
	if got, found, err := store.Get(ctx, "a"); err != nil || !found || string(got) != "lives a year" {
		t.Errorf("a: %q, found %v, %v", got, found, err)
	}
	if got := others(); got != "" {
		t.Errorf("sealed by another key, after resealing: %s", got)
	}
	if resealed, err := resealer.Reseal(ctx, "nothing"); err != nil || resealed {
		t.Errorf("no record: resealed %v, %v", resealed, err)
	}

	// A release that writes another version of what the records hold finds those of the version before.
	version[""] = "1"
	if got := others(); got != "a forever" {
		t.Errorf("of the version before: %s", got)
	}
	version[""] = "0"

	// A record moves to another key with what it had, once; what is there already stays.
	if moved, err := resealer.Rename(ctx, "a", "b"); err != nil || !moved {
		t.Fatalf("rename: moved %v, %v", moved, err)
	}
	if _, found, _ := store.Get(ctx, "a"); found {
		t.Error("the record is still under its old key")
	}
	if got, found, err := store.Get(ctx, "b"); err != nil || !found || string(got) != "lives a year" {
		t.Errorf("b: %q, found %v, %v", got, found, err)
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
	agreed := map[string]bool{"records-v1": true}
	chain, err := kv.ParseKeychain(context.Background(), keychainOf(
		entry(t, kek, "records-v1", start.Add(-time.Hour)), entry(t, kek, "records-v2", start.Add(time.Hour)),
	), kek, kv.WithKeychainClock(func() time.Time { return now }), kv.WithKeychainAgreement(func(id string) bool { return agreed[id] }))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(chain.Ready(), " "); got != "records-v1" {
		t.Errorf("ready before the time: %s", got)
	}
	now = start.Add(2 * time.Hour)
	if got := strings.Join(chain.Ready(), " "); got != "records-v1 records-v2" {
		t.Errorf("ready after the time: %s", got)
	}
	if id, _ := chain.Current(); id != "records-v1" {
		t.Errorf("before the others are ready: current %q", id)
	}
	if names := chain.NameKeys(); names[0].ID != "records-v1" || !names[0].Since.Equal(start.Add(-time.Hour)) {
		t.Errorf("before the others are ready: first name key %q since %s", names[0].ID, names[0].Since)
	}
	agreed["records-v2"] = true
	if id, _ := chain.Current(); id != "records-v2" {
		t.Errorf("once all are ready: current %q", id)
	}
	agreed = map[string]bool{}
	if id, key := chain.Current(); id != "" || key != nil {
		t.Errorf("with nothing agreed: current %q", id)
	}
}
