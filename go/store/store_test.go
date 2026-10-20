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

package store_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/store"
	"github.com/gematik/zero-lab/go/store/filestore"
)

var now = time.Unix(1767225600, 0)

func later(d time.Duration) time.Time { return now.Add(d) }

func wrapper(kek byte) *store.KeyFileWrapper {
	return store.NewKeyFileWrapper([32]byte(bytes.Repeat([]byte{kek}, 32)), rand.Reader)
}

func keyring(t *testing.T) (*store.Keyring, *store.KeyringFile) {
	t.Helper()
	k, f, err := store.CreateKeyring(t.Context(), wrapper(1), rand.Reader, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k, f
}

func newStore(t *testing.T, b store.Backend) *store.Store {
	t.Helper()
	k, _ := keyring(t)
	s, err := store.New(b, k, store.Registry())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// STORE-055, STORE-030, STORE-036: a sealed record comes back as it went in, and its id
// and payload are not in what the backend holds.
func TestSTORE_055_SealedRecordsRoundTripAndHideIDsAndPayloads(t *testing.T) {
	ctx := t.Context()
	b := store.NewMemoryBackend()
	s := newStore(t, b)
	id := []byte("TEST-ONLY-KVNR-0001")
	name, err := s.Put(ctx, store.PoPP, id, []byte("TEST-ONLY PoPP token"), []store.Meta{{Field: "kvnr", Value: id}}, later(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, store.PoPP, id, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != "TEST-ONLY PoPP token" || !got.ExpiresAt.Equal(later(time.Hour)) || got.Name != name {
		t.Fatalf("got %+v", got)
	}
	raw, err := b.Get(ctx, "popp", name, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{id, []byte("PoPP token")} {
		if bytes.Contains(raw.Value, secret) {
			t.Errorf("the backend holds %q in clear", secret)
		}
	}
}

// STORE-015, STORE-035: query by indexed metadata.
func TestSTORE_015_QueryFindsRecordsByMetadata(t *testing.T) {
	ctx := t.Context()
	s := newStore(t, store.NewMemoryBackend())
	for _, r := range []struct{ id, kvnr string }{{"a", "K1"}, {"b", "K1"}, {"c", "K2"}} {
		if _, err := s.Put(ctx, store.PoPP, []byte(r.id), []byte(r.id), []store.Meta{{Field: "kvnr", Value: []byte(r.kvnr)}}, later(time.Minute), now); err != nil {
			t.Fatal(err)
		}
	}
	found, cursor, err := s.Query(ctx, store.PoPP, []store.Meta{{Field: "kvnr", Value: []byte("K1")}}, 10, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	var payloads []string
	for _, f := range found {
		payloads = append(payloads, string(f.Payload))
	}
	slices.Sort(payloads)
	if !slices.Equal(payloads, []string{"a", "b"}) || cursor != nil {
		t.Fatalf("got %v, cursor %v", payloads, cursor)
	}
}

// STORE-023: without a keyring, sealed namespaces are refused and plain ones work.
func TestSTORE_023_WithoutAKeyringSealedNamespacesAreRefused(t *testing.T) {
	ctx := t.Context()
	s, err := store.New(store.NewMemoryBackend(), nil, store.Registry())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, store.TSLState, []byte("tsl"), []byte("42"), nil, time.Time{}, now); !errors.Is(err, store.ErrNoKeyring) {
		t.Errorf("sealed put: %v, want no_keyring", err)
	}
	if _, err := s.Put(ctx, store.WellKnown, []byte("https://idp.example.test"), []byte("{}"), nil, later(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, store.WellKnown, []byte("https://idp.example.test"), now); err != nil || string(got.Payload) != "{}" {
		t.Fatalf("plain get: %v %q", err, got.Payload)
	}
}

// STORE-022: a namespace's lifetime bounds its records, and only its fields are indexed.
func TestSTORE_022_LifetimesAndFieldsFollowTheRegistry(t *testing.T) {
	ctx := t.Context()
	s := newStore(t, store.NewMemoryBackend())
	for _, c := range []struct {
		exp  time.Time
		meta []store.Meta
	}{
		{time.Time{}, nil},
		{later(24*time.Hour + time.Second), nil},
		{later(time.Minute), []store.Meta{{Field: "issuer", Value: []byte("x")}}},
	} {
		if _, err := s.Put(ctx, store.PoPP, []byte("x"), []byte("p"), c.meta, c.exp, now); !errors.Is(err, store.ErrInvalidArgument) {
			t.Errorf("put %v: %v, want invalid_argument", c, err)
		}
	}
	if _, err := s.Put(ctx, store.PoPP, []byte("x"), []byte("p"), []store.Meta{{Field: "iccsn", Value: []byte("80276")}}, later(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, store.Comfort, []byte("card"), []byte("user"), nil, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
}

// STORE-019: a namespace that needs a capability refuses a backend without it.
func TestSTORE_019_MissingCapabilitiesAreRefusedAtConstruction(t *testing.T) {
	ns := store.PoPP
	ns.Requires.MultiProcess = true
	if _, err := store.New(store.NewMemoryBackend(), nil, []store.Namespace{ns}); !errors.Is(err, store.ErrCapabilityMissing) {
		t.Fatalf("%v, want capability_missing", err)
	}
}

// STORE-043: after rotation new records use the new kid, old ones still open, and names
// stay those of the index kid.
func TestSTORE_043_RotationKeepsOlderRecordsReadable(t *testing.T) {
	k, f := keyring(t)
	oldKid := k.CurrentKid()
	name, _ := k.Name("popp", []byte("x"))
	old, err := k.Seal("popp", name, later(time.Minute), []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Rotate(t.Context(), f, wrapper(1), now); err != nil {
		t.Fatal(err)
	}
	if k.CurrentKid() == oldKid {
		t.Fatal("kid did not change")
	}
	if o, err := k.Open("popp", name, now, old); err != nil || o.Kid != oldKid {
		t.Fatalf("old record: %v %q", err, o.Kid)
	}
	if again, _ := k.Name("popp", []byte("x")); again != name {
		t.Error("rotation changed names")
	}
}

// STORE-127, STORE-064: rewrapping changes only the wrapping; the old key file no longer
// opens the new keyring.
func TestSTORE_127_RewrapMovesTheKeyringToANewKeyFile(t *testing.T) {
	ctx := t.Context()
	k, f := keyring(t)
	name, _ := k.Name("comfort", []byte("card"))
	rec, err := k.Seal("comfort", name, time.Time{}, []byte("user"))
	if err != nil {
		t.Fatal(err)
	}
	moved, err := k.Rewrap(ctx, wrapper(2))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := store.ParseKeyringFile(moved.Encode())
	if err != nil || parsed.ProfileID != f.ProfileID {
		t.Fatalf("rewrapped file: %v", err)
	}
	re, err := store.OpenKeyring(ctx, parsed, wrapper(2), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if o, err := re.Open("comfort", name, now, rec); err != nil || string(o.Payload) != "user" {
		t.Fatalf("record after rewrap: %v", err)
	}
	if _, err := store.OpenKeyring(ctx, parsed, wrapper(1), rand.Reader); !errors.Is(err, store.ErrAuthFailed) {
		t.Errorf("old key file: %v, want auth_failed", err)
	}
}

// STORE-061: every keyring has its own profile id, so records do not move between
// profiles.
func TestSTORE_061_RecordsDoNotOpenInAnotherProfile(t *testing.T) {
	a, _ := keyring(t)
	b, _ := keyring(t)
	name, _ := a.Name("popp", []byte("x"))
	rec, _ := a.Seal("popp", name, later(time.Minute), []byte("p"))
	if _, err := b.Open("popp", name, now, rec); err == nil {
		t.Fatal("a record opened in another profile")
	}
}

// STORE-012, STORE-082: of many concurrent takes of one record on the files backend,
// exactly one gets it.
func TestSTORE_082_FilesBackendHandsARecordToOneOfManyTakes(t *testing.T) {
	ctx := t.Context()
	b, err := filestore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	for round := range 20 {
		name := store.Name{byte(round)}
		if err := b.Put(ctx, "popp", name, store.StoredRecord{Value: []byte("once")}); err != nil {
			t.Fatal(err)
		}
		var won atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				if _, err := b.Take(ctx, "popp", name, now); err == nil {
					won.Add(1)
				} else if !errors.Is(err, store.ErrNotFound) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if n := won.Load(); n != 1 {
			t.Fatalf("round %d: %d takes won", round, n)
		}
	}
}

// STORE-086, STORE-100: a files tree of a level whose min_compatible is above this
// implementation's is refused.
func TestSTORE_100_FilesTreeOfAnIncompatibleLevelIsRefused(t *testing.T) {
	dir := t.TempDir()
	b, err := filestore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	if err := writeFile(dir+"/meta", store.FilesMeta{Level: 3, MinCompatible: 2}.Encode()); err != nil {
		t.Fatal(err)
	}
	if _, err := filestore.Open(dir); !errors.Is(err, store.ErrUnsupportedVersion) {
		t.Fatalf("%v, want unsupported_version", err)
	}
}

// The files backend works through an os.Root: a namespace directory replaced by a
// symbolic link to elsewhere does not let take claim and delete a file there.
func TestFilestoreStaysInsideItsRoot(t *testing.T) {
	ctx := t.Context()
	dir, outside := t.TempDir(), t.TempDir()
	b, err := filestore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	name := store.Name{0xab}
	rel := strings.TrimPrefix(store.RecordPath("popp", name), "popp/")
	target := filepath.Join(outside, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(target, store.EncodeRecordFile(store.StoredRecord{Value: []byte("not ours")})); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "v1", "popp")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	if r, err := b.Take(ctx, "popp", name, now); err == nil {
		t.Fatalf("take read %q through a link out of the root", r.Value)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("take removed a file outside the root: %v", err)
	}
}
