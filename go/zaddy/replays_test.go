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

package zaddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/gematik/zero-lab/go/dpop"
)

const replayTestURI = "https://api.example.com/resource"

// replicaStorage is the storage of one replica: a FileStorage of its own over a directory every replica shares,
// as Caddy's default storage on a shared volume.
func replicaStorage(dir string) certmagic.Storage {
	return &certmagic.FileStorage{Path: dir}
}

func replicaVerifier(t *testing.T, replays dpop.Replays) *dpop.Verifier {
	t.Helper()
	v, err := dpop.NewVerifier(dpop.Config{Replays: replays})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func proofHeader(t *testing.T, key *dpop.Key) http.Header {
	t.Helper()
	proof, err := key.Proof(http.MethodGet, replayTestURI, dpop.ProofOptions{})
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	header.Set(dpop.HeaderName, proof)
	return header
}

func verifyAt(v *dpop.Verifier, header http.Header) error {
	_, err := v.Verify(context.Background(), header, dpop.Request{Method: http.MethodGet, URI: replayTestURI})
	return err
}

func TestRFC9449_11_1_AProofAcceptedByOneReplicaIsRefusedByAnother(t *testing.T) {
	dir := t.TempDir()
	first := replicaVerifier(t, newStorageReplays(replicaStorage(dir), nil, nil))
	second := replicaVerifier(t, newStorageReplays(replicaStorage(dir), nil, nil))
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	header := proofHeader(t, key)
	if err := verifyAt(first, header); err != nil {
		t.Fatalf("first replica refused a fresh proof: %v", err)
	}
	err = verifyAt(second, header)
	if refused, ok := errors.AsType[*dpop.Error](err); !ok || !strings.Contains(refused.Description, "used before") {
		t.Fatalf("second replica: %v", err)
	}
	if err := verifyAt(second, proofHeader(t, key)); err != nil {
		t.Fatalf("second replica refused a fresh proof: %v", err)
	}
}

// The check and the record are one step under the record's lock: of proofs replayed at once to two replicas,
// one is accepted.
func TestRFC9449_11_1_AProofSentToTwoReplicasAtOnceIsAcceptedOnce(t *testing.T) {
	dir := t.TempDir()
	replicas := []*storageReplays{
		newStorageReplays(replicaStorage(dir), nil, nil),
		newStorageReplays(replicaStorage(dir), nil, nil),
	}
	until := time.Now().Add(time.Minute)
	const attempts = 3
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
	)
	for i := range attempts {
		wg.Go(func() {
			seen, err := replicas[i%len(replicas)].Seen(t.Context(), "proof", until)
			if err == nil && !seen {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d times", accepted)
	}
}

func TestRFC9449_11_1_AnExpiredRecordAcceptsTheIdentifierAgain(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	before := newStorageReplays(replicaStorage(dir), func() time.Time { return now }, nil)
	if seen, err := before.Seen(t.Context(), "proof", now.Add(time.Minute)); seen || err != nil {
		t.Fatal(seen, err)
	}
	// Within the lifetime plus the clock skew the replicas' clocks may differ by, the record holds.
	skewed := newStorageReplays(replicaStorage(dir), func() time.Time { return now.Add(time.Minute + storageReplaysClockSkew/2) }, nil)
	if seen, err := skewed.Seen(t.Context(), "proof", now.Add(time.Minute)); !seen || err != nil {
		t.Fatalf("record lost within the clock skew: %v %v", seen, err)
	}
	after := newStorageReplays(replicaStorage(dir), func() time.Time { return now.Add(time.Minute + storageReplaysClockSkew) }, nil)
	if seen, err := after.Seen(t.Context(), "proof", now.Add(3*time.Minute)); seen || err != nil {
		t.Fatalf("expired record still seen: %v %v", seen, err)
	}
}

// The proof identifier is client input of any size: keys and lock names carry its SHA-256 only.
func TestRFC9449_11_1_StorageKeysHoldOnlyAHashOfTheProofIdentifier(t *testing.T) {
	storage := &recordingStorage{Storage: replicaStorage(t.TempDir())}
	id := "../../" + strings.Repeat("x", 300)
	if _, err := newStorageReplays(storage, nil, nil).Seen(t.Context(), id, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(id))
	name := hex.EncodeToString(sum[:])
	want := []string{"lock " + storageReplaysLockPrefix + name, "store " + path.Join(storageReplaysPrefix, name)}
	for _, w := range want {
		if !strings.Contains(strings.Join(storage.calls, "\n"), w) {
			t.Errorf("no %q in %q", w, storage.calls)
		}
	}
	for _, call := range storage.calls {
		if strings.Contains(call, "xxx") || strings.Contains(call, "..") {
			t.Errorf("identifier in %q", call)
		}
	}
}

// servers.md rule 16: a storage that cannot tell whether a proof was used denies it.
func TestServersRule16_AStorageErrorRefusesTheProof(t *testing.T) {
	for _, fail := range []string{"lock", "load", "store", "unlock", "corrupt"} {
		t.Run(fail, func(t *testing.T) {
			storage := &failingStorage{Storage: replicaStorage(t.TempDir()), fail: fail}
			v := replicaVerifier(t, newStorageReplays(storage, nil, nil))
			key, err := dpop.NewKey()
			if err != nil {
				t.Fatal(err)
			}
			err = verifyAt(v, proofHeader(t, key))
			if err == nil {
				t.Fatal("accepted a proof the storage could not record")
			}
			if _, ok := errors.AsType[*dpop.Error](err); ok {
				t.Fatalf("a storage error reads as the client's: %v", err)
			}
		})
	}
}

func TestRFC9449_11_1_SweepRemovesExpiredRecordsOnly(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	replays := newStorageReplays(replicaStorage(dir), func() time.Time { return now }, nil)
	for id, until := range map[string]time.Time{"old": now.Add(-time.Hour), "live": now.Add(time.Minute)} {
		if _, err := replays.Seen(t.Context(), id, until); err != nil {
			t.Fatal(err)
		}
	}
	storage := replicaStorage(dir)
	foreign := path.Join(storageReplaysPrefix, "not-a-record")
	if err := storage.Store(t.Context(), foreign, []byte("x")); err != nil {
		t.Fatal(err)
	}
	removed, err := replays.sweep(t.Context())
	if err != nil || removed != 1 {
		t.Fatalf("removed %d: %v", removed, err)
	}
	if seen, err := replays.Seen(t.Context(), "live", now.Add(time.Minute)); !seen || err != nil {
		t.Fatalf("sweep removed an unexpired record: %v %v", seen, err)
	}
	if !storage.Exists(t.Context(), foreign) {
		t.Fatal("sweep removed a key that is no record")
	}
}

func TestRFC9449_11_1_SweepOfAnEmptyStorageSucceeds(t *testing.T) {
	removed, err := newStorageReplays(replicaStorage(t.TempDir()), nil, nil).sweep(t.Context())
	if err != nil || removed != 0 {
		t.Fatalf("removed %d: %v", removed, err)
	}
}

// recordingStorage records the keys and lock names it is called with.
type recordingStorage struct {
	certmagic.Storage
	calls []string
}

func (s *recordingStorage) Lock(ctx context.Context, name string) error {
	s.calls = append(s.calls, "lock "+name)
	return s.Storage.Lock(ctx, name)
}

func (s *recordingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	s.calls = append(s.calls, "load "+key)
	return s.Storage.Load(ctx, key)
}

func (s *recordingStorage) Store(ctx context.Context, key string, value []byte) error {
	s.calls = append(s.calls, "store "+key)
	return s.Storage.Store(ctx, key, value)
}

// failingStorage fails the operation named by fail; "corrupt" loads a record that holds no expiry.
type failingStorage struct {
	certmagic.Storage
	fail string
}

var errStorage = errors.New("storage unavailable")

func (s *failingStorage) Lock(ctx context.Context, name string) error {
	if s.fail == "lock" {
		return errStorage
	}
	return s.Storage.Lock(ctx, name)
}

func (s *failingStorage) Unlock(ctx context.Context, name string) error {
	err := s.Storage.Unlock(ctx, name)
	if s.fail == "unlock" {
		return errStorage
	}
	return err
}

func (s *failingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	switch s.fail {
	case "load":
		return nil, errStorage
	case "corrupt":
		return []byte("garbage"), nil
	}
	return s.Storage.Load(ctx, key)
}

func (s *failingStorage) Store(ctx context.Context, key string, value []byte) error {
	if s.fail == "store" {
		return errStorage
	}
	return s.Storage.Store(ctx, key, value)
}
