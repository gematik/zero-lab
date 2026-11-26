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

package kvtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// Pod is how one pod of a deployment opens its store.
type Pod struct {
	// Number tells the pods of a test apart. Where a database has several writing nodes, it picks the pod's
	// node, so that the pods of a test are spread over them.
	Number int
	// Ephemeral asks for the store of the ephemeral class.
	Ephemeral bool
	// Mark is what the store keeps beside each record, nil for a store without marks.
	Mark func(key string, value []byte) string
}

// Open opens the store of a pod over the database of a test, with connections of its own: the suites of
// this file run what a deployment of several replicas does to one database, and a replica shares no pool
// with another. It is called from several goroutines at once.
type Open func(pod Pod) (kv.Store, error)

// openPods opens the stores of n pods at once, as replicas that start together do, and closes them after
// the test.
func openPods(t *testing.T, open Open, n int, pod Pod) []kv.Store {
	t.Helper()
	stores, errs := make([]kv.Store, n), make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			one := pod
			one.Number += i
			stores[i], errs[i] = open(one)
		})
	}
	wg.Wait()
	t.Cleanup(func() {
		for _, s := range stores {
			if s != nil {
				_ = s.Close()
			}
		}
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("pod %d does not open its store: %v", pod.Number+i, err)
		}
	}
	return stores
}

// clock is a clock a test sets: the one sealed expiries are written and read by.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock { return &clock{at: time.Now()} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// inTx runs fn in one transaction of a store.
func inTx(ctx context.Context, s kv.Store, fn func(tx kv.Tx) error) error {
	tr, ok := s.(kv.Transactor)
	if !ok {
		return kv.ErrNotTransactor
	}
	return tr.Tx(ctx, fn)
}

// reads are the ways a record is read, each as a function of the key.
func reads(ctx context.Context, s kv.Store) map[string]func(key string) ([]byte, bool, error) {
	return map[string]func(key string) ([]byte, bool, error){
		"Get":  func(key string) ([]byte, bool, error) { return s.Get(ctx, key) },
		"Take": func(key string) ([]byte, bool, error) { return s.Take(ctx, key) },
		"Tx.Get": func(key string) (value []byte, found bool, err error) {
			err = inTx(ctx, s, func(tx kv.Tx) error {
				value, found, err = tx.Get(ctx, key)
				return err
			})
			return value, found, err
		},
		"Tx.Take": func(key string) (value []byte, found bool, err error) {
			err = inTx(ctx, s, func(tx kv.Tx) error {
				value, found, err = tx.Take(ctx, key)
				return err
			})
			return value, found, err
		},
	}
}

// failsClosed reports an error unless a read failed as a record that does not open has to: with
// kv.ErrIntegrity and nothing of a value.
func failsClosed(value []byte, found bool, err error) error {
	if !errors.Is(err, kv.ErrIntegrity) || found || value != nil {
		return errors.Join(fmt.Errorf("value %q, found %v: expected nothing and kv.ErrIntegrity, got", value, found), err)
	}
	return nil
}

// Sealing runs sealed stores over the stores of several pods, in each class (server rule 5): what one pod
// seals another opens, by every way of writing and reading; the database holds none of it in the clear; a
// record that whoever writes to the database moved to another key, another purpose or another class does
// not open; and a record ends when its seal says, whatever the database says.
func Sealing(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	const purpose = "kvtest sealing"
	const name = "Mustermann"
	for _, class := range []kv.Durability{kv.Durable, kv.Ephemeral} {
		t.Run(class.String(), func(t *testing.T) {
			pod := Pod{Ephemeral: class == kv.Ephemeral, Mark: kv.SealedMarker(nil)}
			raws := openPods(t, open, 3, pod)
			p := prefix(t, raws[0])
			at := newClock()
			keys := ring(t, "a")
			writer := kv.NewSealed(raws[0], keys, purpose, kv.WithSealedExpiry(at.now))
			reader := kv.NewSealed(raws[1], keys, purpose, kv.WithSealedExpiry(at.now))
			below := raws[2]
			if got := kv.DurabilityOf(writer); got != class {
				t.Fatalf("the sealed store says it is %v", got)
			}
			rawOf := func(key string) []byte {
				t.Helper()
				record, found, err := below.Get(ctx, key)
				if err != nil || !found {
					t.Fatalf("the record below: found %v, err %v", found, err)
				}
				return record
			}
			secret := func(way string) []byte { return []byte("the session of Erika " + name + ", written by " + way) }

			t.Run("what one pod seals another opens, by every way of writing, and the database holds none of it in the clear", func(t *testing.T) {
				ways := map[string]func(key string, value []byte) error{
					"Set": func(key string, value []byte) error { return writer.Set(ctx, key, value, time.Hour) },
					"SetIfAbsent": func(key string, value []byte) error {
						set, err := writer.SetIfAbsent(ctx, key, value, time.Hour)
						if err == nil && !set {
							err = errors.New("not set")
						}
						return err
					},
					"SetMany": func(key string, value []byte) error {
						return writer.SetMany(ctx, kv.Entry{Key: key, Value: value, TTL: time.Hour}, kv.Entry{Key: key + ":index", Value: value})
					},
					"Swap": func(key string, value []byte) error {
						if err := writer.Set(ctx, key, []byte("read"), time.Hour); err != nil {
							return err
						}
						swapped, err := writer.(kv.Swapper).Swap(ctx, key, []byte("read"), value, time.Hour)
						if err == nil && !swapped {
							err = errors.New("not swapped")
						}
						return err
					},
					"Tx.Set": func(key string, value []byte) error {
						return inTx(ctx, writer, func(tx kv.Tx) error { return tx.Set(ctx, key, value, time.Hour) })
					},
					"Tx.SetIfAbsent": func(key string, value []byte) error {
						return inTx(ctx, writer, func(tx kv.Tx) error {
							set, err := tx.SetIfAbsent(ctx, key, value, time.Hour)
							if err == nil && !set {
								err = errors.New("not set")
							}
							return err
						})
					},
				}
				for way, write := range ways {
					if err := write(p+"way:"+way, secret(way)); err != nil {
						t.Fatalf("%s: %v", way, err)
					}
				}
				for way := range ways {
					if got, found, err := reader.Get(ctx, p+"way:"+way); err != nil || !found || !bytes.Equal(got, secret(way)) {
						t.Errorf("written by %s, read by another pod: %q, found %v, err %v", way, got, found, err)
					}
				}
				stored, err := below.Keys(ctx, p+"way:")
				if err != nil || len(stored) != len(ways)+1 {
					t.Fatalf("%d records are below, of %d: %v", len(stored), len(ways)+1, err)
				}
				for _, key := range stored {
					if bytes.Contains(rawOf(key), []byte(name)) {
						t.Errorf("the database holds %s in the clear", strings.TrimPrefix(key, p))
					}
				}
				for way, read := range reads(ctx, reader) {
					key := p + "read:" + way
					if err := writer.Set(ctx, key, secret(way), time.Hour); err != nil {
						t.Fatal(err)
					}
					if got, found, err := read(key); err != nil || !found || !bytes.Equal(got, secret(way)) {
						t.Errorf("read by %s: %q, found %v, err %v", way, got, found, err)
					}
				}
			})

			if err := writer.Set(ctx, p+"held", secret("Set"), time.Hour); err != nil {
				t.Fatal(err)
			}
			held := rawOf(p + "held")

			t.Run("a record moved to another key does not open, however it is read", func(t *testing.T) {
				for way, read := range reads(ctx, reader) {
					key := p + "moved:" + way
					if err := below.Set(ctx, key, held, time.Hour); err != nil {
						t.Fatal(err)
					}
					if err := failsClosed(read(key)); err != nil {
						t.Errorf("%s: %v", way, err)
					}
				}
				if err := below.Set(ctx, p+"moved:Swap", held, time.Hour); err != nil {
					t.Fatal(err)
				}
				swapped, err := reader.(kv.Swapper).Swap(ctx, p+"moved:Swap", secret("Set"), []byte("next"), time.Hour)
				if !errors.Is(err, kv.ErrIntegrity) || swapped {
					t.Errorf("Swap: swapped %v, err %v", swapped, err)
				}
			})

			t.Run("a record does not open under another purpose, nor one of another purpose under this", func(t *testing.T) {
				other := kv.NewSealed(raws[1], keys, "another purpose", kv.WithSealedExpiry(at.now))
				if err := failsClosed(other.Get(ctx, p+"held")); err != nil {
					t.Errorf("under another purpose: %v", err)
				}
				if err := other.Set(ctx, p+"theirs", secret("another purpose"), time.Hour); err != nil {
					t.Fatal(err)
				}
				if err := failsClosed(reader.Get(ctx, p+"theirs")); err != nil {
					t.Errorf("of another purpose: %v", err)
				}
			})

			t.Run("a record put into the table of the other class does not open there, under the same key", func(t *testing.T) {
				across, err := open(Pod{Number: 3, Ephemeral: !pod.Ephemeral, Mark: pod.Mark})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = across.Delete(ctx, p+"held")
					_ = across.Close()
				})
				if kv.DurabilityOf(across) == class {
					t.Fatalf("the store of the other class says it is %v too", class)
				}
				if err := across.Set(ctx, p+"held", held, time.Hour); err != nil {
					t.Fatal(err)
				}
				if err := failsClosed(kv.NewSealed(across, keys, purpose, kv.WithSealedExpiry(at.now)).Get(ctx, p+"held")); err != nil {
					t.Error(err)
				}
				if got, found, err := reader.Get(ctx, p+"held"); err != nil || !found || !bytes.Equal(got, secret("Set")) {
					t.Errorf("in its own class: %q, found %v, err %v", got, found, err)
				}
			})

			t.Run("a record ends when its seal says, whatever the database says", func(t *testing.T) {
				for key, ttl := range map[string]time.Duration{"short": time.Hour, "deleted": time.Hour, "forever": 0} {
					if err := writer.Set(ctx, p+key, secret(key), ttl); err != nil {
						t.Fatal(err)
					}
				}
				short, deleted := rawOf(p+"short"), rawOf(p+"deleted")
				// Whoever writes to the database gives the record another end: the expiry stands after the
				// version, the length of the key ID and the ID.
				stretched := bytes.Clone(short)
				stretched[2+len("a")+7] ^= 1
				if err := below.Set(ctx, p+"short", stretched, 0); err != nil {
					t.Fatal(err)
				}
				if err := failsClosed(reader.Get(ctx, p+"short")); err != nil {
					t.Errorf("a record whose sealed expiry was changed: %v", err)
				}
				// They take the end the database keeps away, and put back a record that was deleted.
				if err := below.Set(ctx, p+"short", short, 0); err != nil {
					t.Fatal(err)
				}
				if err := writer.Delete(ctx, p+"deleted"); err != nil {
					t.Fatal(err)
				}
				if err := below.Set(ctx, p+"deleted", deleted, 0); err != nil {
					t.Fatal(err)
				}
				if got, found, err := reader.Get(ctx, p+"short"); err != nil || !found || !bytes.Equal(got, secret("short")) {
					t.Fatalf("within its time: %q, found %v, err %v", got, found, err)
				}
				at.advance(2 * time.Hour)
				for way, read := range reads(ctx, reader) {
					for _, key := range []string{"short", "deleted"} {
						if got, found, err := read(p + key); err != nil || found || got != nil {
							t.Errorf("%s of %q after its sealed expiry, kept by the database for ever: %q, found %v, err %v", way, key, got, found, err)
						}
						if err := below.Set(ctx, p+key, map[string][]byte{"short": short, "deleted": deleted}[key], 0); err != nil {
							t.Fatal(err)
						}
					}
				}
				at.advance(100 * 365 * 24 * time.Hour)
				if got, found, err := reader.Get(ctx, p+"forever"); err != nil || !found || !bytes.Equal(got, secret("forever")) {
					t.Errorf("a record without an end: %q, found %v, err %v", got, found, err)
				}
			})
		})
	}
}

// Unsealed runs sealed stores over a database that holds unsealed records of a release before sealing
// (server rules 5 and 22). Nothing unsealed is taken for a sealed record: every read of one fails with
// kv.ErrIntegrity. The records are found without reading every record, as records that are not what the
// store writes now, and the host takes them along through the store of before: what it seals is only what
// it knows as a record of before, and whatever else it finds there it removes, since sealing makes a value
// authentic and the database is where it came from.
func Unsealed(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	const purpose = "kvtest takeover"
	const sessions = 8
	before, err := open(Pod{Number: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = before.Close() })
	raws := openPods(t, open, 2, Pod{Mark: kv.SealedMarker(nil)})
	p := prefix(t, raws[0])
	keys := ring(t, "a")
	sealed := make([]kv.Store, len(raws))
	for i, raw := range raws {
		sealed[i] = kv.NewSealed(raw, keys, purpose, kv.WithSealedExpiry(time.Now))
	}
	plain := func(i int) []byte { return fmt.Appendf(nil, "the session of Erika Mustermann, number %d", i) }
	for i := range sessions {
		if err := before.Set(ctx, fmt.Sprintf("%ssession:%d", p, i), plain(i), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	// Bytes that have the form of a sealed record with an expiry, under a key the ring does not hold.
	forged := slices.Concat([]byte{2, 1, 'z'}, make([]byte, 8), bytes.Repeat([]byte{0x5a}, 16+12+16+8))
	if err := before.Set(ctx, p+"session:forged", forged, time.Hour); err != nil {
		t.Fatal(err)
	}
	left := sessions + 1

	t.Run("an unsealed record is not taken for a sealed one, however it is read", func(t *testing.T) {
		i := 0
		for way, read := range reads(ctx, sealed[0]) {
			if err := failsClosed(read(fmt.Sprintf("%ssession:%d", p, i))); err != nil {
				t.Errorf("%s: %v", way, err)
			}
			if way == "Take" {
				// A Take has deleted what it found by the time it sees that it does not open.
				left--
			}
			i++
		}
		if err := failsClosed(sealed[1].Get(ctx, p+"session:forged")); err != nil {
			t.Errorf("bytes in the form of a sealed record: %v", err)
		}
		key := fmt.Sprintf("%ssession:%d", p, sessions-1)
		swapped, err := sealed[0].(kv.Swapper).Swap(ctx, key, plain(sessions-1), []byte("next"), time.Hour)
		if !errors.Is(err, kv.ErrIntegrity) || swapped {
			t.Errorf("Swap of the value an unsealed record holds: swapped %v, err %v", swapped, err)
		}
		if set, err := sealed[0].SetIfAbsent(ctx, key, []byte("next"), time.Hour); err != nil || set {
			t.Errorf("SetIfAbsent over an unsealed record: set %v, err %v", set, err)
		}
		if got, found, err := before.Get(ctx, key); err != nil || !found || !bytes.Equal(got, plain(sessions-1)) {
			t.Errorf("the unsealed record after the refused writes: %q, found %v, err %v", got, found, err)
		}
	})

	t.Run("the unsealed records are found as records the store does not write now, and cannot be sealed again as they are", func(t *testing.T) {
		for i, s := range sealed {
			resealer := s.(kv.Resealer)
			if n, err := resealer.CountOthers(ctx, p); err != nil || n != left {
				t.Errorf("pod %d counts %d others, of %d unsealed records: %v", i, n, left, err)
			}
			by, err := resealer.SealedByKeys(ctx, p)
			if err != nil || by["a"] != 0 {
				t.Errorf("pod %d: sealed by %v, err %v", i, by, err)
			}
		}
		resealed, err := sealed[0].(kv.Resealer).Reseal(ctx, fmt.Sprintf("%ssession:%d", p, sessions-1))
		if !errors.Is(err, kv.ErrIntegrity) || resealed {
			t.Errorf("Reseal of an unsealed record: resealed %v, err %v", resealed, err)
		}
	})

	t.Run("the host takes along what it knows as a record of before, from every pod at once, removes the rest, and none is left unsealed", func(t *testing.T) {
		walk := func(s kv.Store) error {
			resealer := s.(kv.Resealer)
			for after := ""; ; {
				found, err := resealer.Others(ctx, p, after, 3)
				if err != nil || len(found) == 0 {
					return err
				}
				for _, key := range found {
					value, there, err := before.Get(ctx, key)
					if err != nil {
						return err
					}
					if !there {
						continue
					}
					if _, _, err := s.Get(ctx, key); !errors.Is(err, kv.ErrIntegrity) {
						// Another pod has sealed it in the meantime.
						continue
					}
					if !bytes.HasPrefix(value, []byte("the session of ")) {
						if err := before.Delete(ctx, key); err != nil {
							return err
						}
						continue
					}
					if err := s.Set(ctx, key, value, time.Hour); err != nil {
						return err
					}
				}
				after = found[len(found)-1]
			}
		}
		errs := make(chan error, len(sealed))
		for _, s := range sealed {
			go func() { errs <- walk(s) }()
		}
		for range sealed {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		resealer := sealed[1].(kv.Resealer)
		if n, err := resealer.CountOthers(ctx, p); err != nil || n != 0 {
			t.Errorf("%d others are left: %v", n, err)
		}
		taken := left - 1
		if by, err := resealer.SealedByKeys(ctx, p); err != nil || len(by) != 1 || by["a"] != taken {
			t.Errorf("sealed by %v, of %d records: %v", by, taken, err)
		}
		if _, found, err := before.Get(ctx, p+"session:forged"); err != nil || found {
			t.Errorf("what was no record of before is still there: found %v, err %v", found, err)
		}
		stored, err := before.Keys(ctx, p)
		if err != nil || len(stored) != taken {
			t.Fatalf("%d records are there, of %d: %v", len(stored), taken, err)
		}
		for _, key := range stored {
			record, _, err := before.Get(ctx, key)
			if err != nil || bytes.Contains(record, []byte("Mustermann")) {
				t.Errorf("%s is still in the clear: %v", strings.TrimPrefix(key, p), err)
			}
			n, err := strconv.Atoi(key[strings.LastIndex(key, ":")+1:])
			if err != nil {
				t.Fatalf("%s: %v", strings.TrimPrefix(key, p), err)
			}
			if got, found, err := sealed[1].Get(ctx, key); err != nil || !found || !bytes.Equal(got, plain(n)) {
				t.Errorf("%s through the sealed store: %q, found %v, err %v", strings.TrimPrefix(key, p), got, found, err)
			}
		}
	})
}

// keyStages are the keys of a pod at each stage of a change of keys, as the guide for hosts has them:
// the key of before alone; the new key known, the old one sealing; the new key sealing, the old one
// known; the new key alone.
type keyStages struct {
	old, known, sealing, alone kv.Keys
}

func ringStages(t *testing.T) keyStages {
	t.Helper()
	return keyStages{old: ring(t, "a"), known: ring(t, "a", "b"), sealing: ring(t, "b", "a"), alone: ring(t, "b")}
}

// chainStages are the stages as keychain files: the second entry is in the file from the stage known on
// and in force an hour after the time the pods' clocks show until then.
func chainStages(t *testing.T) keyStages {
	t.Helper()
	ctx := context.Background()
	const purpose = "kvtest keychain"
	kek := make(kv.LocalKEK, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	extend := func(file []byte, from time.Time) []byte {
		t.Helper()
		file, err := kek.Extend(file, purpose, "kvtest-kek", from, true)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	first := extend(nil, start.Add(-time.Hour))
	both := extend(first, start.Add(time.Hour))
	var file struct {
		Purpose string            `json:"purpose"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(both, &file); err != nil || len(file.Entries) != 2 {
		t.Fatalf("the keychain file: %d entries, err %v", len(file.Entries), err)
	}
	file.Entries = file.Entries[1:]
	second, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	chain := func(file []byte, at time.Time) kv.Keys {
		t.Helper()
		keys, err := kv.ParseKeychain(ctx, file, purpose, kek, kv.WithKeychainClock(func() time.Time { return at }))
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
	return keyStages{
		old:     chain(first, start),
		known:   chain(both, start),
		sealing: chain(both, start.Add(2*time.Hour)),
		alone:   chain(second, start.Add(2*time.Hour)),
	}
}

// Rotation changes the keys of a sealed store as the guide for hosts says ("When the keys change"),
// with a kv.Keyring and with a kv.Keychain, while the pods hold different files: at every stage of every
// rollout each pod reads every record; a pod whose file is a stage too far fails closed; and the walk,
// run by every pod at once beside a writer, leaves nothing under the old key, loses nothing, and leaves
// each record its end (server rule 22).
func Rotation(t *testing.T, open Open) {
	t.Helper()
	t.Run("with a keyring", func(t *testing.T) { rotation(t, open, ringStages(t)) })
	t.Run("with a keychain", func(t *testing.T) { rotation(t, open, chainStages(t)) })
}

func rotation(t *testing.T, open Open, stages keyStages) {
	t.Helper()
	ctx := context.Background()
	const purpose = "kvtest rotation"
	const pods = 4
	raws := openPods(t, open, pods, Pod{Mark: kv.SealedMarker(nil)})
	p := prefix(t, raws[0])
	at := newClock()
	oldID, _ := stages.old.Current()
	newID, _ := stages.sealing.Current()
	if oldID == newID || oldID == "" || newID == "" {
		t.Fatalf("the keys of before and of now are %q and %q", oldID, newID)
	}
	// rollout is the pods as a rollout leaves them: pod i holds the i-th of the files, which repeat.
	rollout := func(files ...kv.Keys) []kv.Store {
		stores := make([]kv.Store, pods)
		for i, raw := range raws {
			stores[i] = kv.NewSealed(raw, files[i%len(files)], purpose, kv.WithSealedExpiry(at.now))
		}
		return stores
	}
	var mu sync.Mutex
	held := map[string]string{}
	hold := func(key, value string) {
		mu.Lock()
		defer mu.Unlock()
		held[key] = value
	}
	// serve has every pod write a session that ends and a registration that does not, and then every pod
	// read every record there is.
	serve := func(t *testing.T, stage string, stores []kv.Store) {
		t.Helper()
		for i, s := range stores {
			for kind, ttl := range map[string]time.Duration{"session": time.Hour, "registration": 0} {
				key, value := fmt.Sprintf("%s%s:%s:%d", p, kind, stage, i), fmt.Sprintf("%s of pod %d, %s", kind, i, stage)
				if err := s.Set(ctx, key, []byte(value), ttl); err != nil {
					t.Fatalf("pod %d writes: %v", i, err)
				}
				hold(key, value)
			}
		}
		for i, s := range stores {
			for key, want := range held {
				if got, found, err := s.Get(ctx, key); err != nil || !found || string(got) != want {
					t.Errorf("pod %d reads %s: %q, found %v, err %v", i, strings.TrimPrefix(key, p), got, found, err)
				}
			}
		}
	}
	sealedBy := func(t *testing.T, s kv.Store) map[string]int {
		t.Helper()
		by, err := s.(kv.Resealer).SealedByKeys(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return by
	}

	t.Run("a new key that every pod comes to know, and that does not seal yet, changes nothing", func(t *testing.T) {
		serve(t, "before", rollout(stages.old))
		serve(t, "while the new key becomes known", rollout(stages.old, stages.known))
		serve(t, "known", rollout(stages.known))
		if by := sealedBy(t, rollout(stages.known)[0]); len(by) != 1 || by[oldID] != len(held) {
			t.Errorf("sealed by %v, of %d records under %q", by, len(held), oldID)
		}
	})

	const renamed = 6
	for i := range renamed {
		key, value := fmt.Sprintf("%sname-of-before:%d", p, i), fmt.Sprintf("a record whose key changes, %d", i)
		if err := rollout(stages.known)[i%pods].Set(ctx, key, []byte(value), time.Hour); err != nil {
			t.Fatal(err)
		}
		hold(key, value)
	}
	if err := rollout(stages.known)[0].Set(ctx, p+"code", []byte("single use"), time.Hour); err != nil {
		t.Fatal(err)
	}
	underOld := len(held) + 1

	t.Run("while the new key begins to seal, pods of both files read every record", func(t *testing.T) {
		serve(t, "while the new key begins to seal", rollout(stages.known, stages.sealing))
		serve(t, "sealing", rollout(stages.sealing))
		if by := sealedBy(t, rollout(stages.sealing)[1]); len(by) != 2 || by[oldID] != underOld+pods || by[newID] != len(held)+1-by[oldID] {
			t.Errorf("sealed by %v: %d records, %d of them written while only %q sealed", by, len(held)+1, underOld, oldID)
		}
	})

	t.Run("a pod whose file is a stage too far fails closed: it gets no value, and can tell before it serves", func(t *testing.T) {
		early := kv.NewSealed(raws[0], stages.alone, purpose, kv.WithSealedExpiry(at.now))
		for way, read := range reads(ctx, early) {
			key := p + "session:before:1"
			if way == "Take" {
				key = p + "code"
			}
			if err := failsClosed(read(key)); err != nil {
				t.Errorf("without the old key, %s of a record it sealed: %v", way, err)
			}
		}
		if by := sealedBy(t, early); by[oldID] == 0 {
			t.Errorf("the pod without the old key is not told that it still seals records: %v", by)
		}
		late := kv.NewSealed(raws[1], stages.old, purpose, kv.WithSealedExpiry(at.now))
		if err := failsClosed(late.Get(ctx, p+"session:sealing:0")); err != nil {
			t.Errorf("without the new key, a record it sealed: %v", err)
		}
	})

	t.Run("the walk, by every pod at once and beside a writer, leaves nothing under the old key and loses nothing", func(t *testing.T) {
		stores := rollout(stages.sealing)
		walk := func(s kv.Store) error {
			resealer := s.(kv.Resealer)
			for after := ""; ; {
				others, err := resealer.Others(ctx, p, after, 5)
				if err != nil || len(others) == 0 {
					return err
				}
				for _, key := range others {
					if name, moves := strings.CutPrefix(key, p+"name-of-before:"); moves {
						_, err = resealer.Rename(ctx, key, p+"name:"+name)
					} else {
						_, err = resealer.Reseal(ctx, key)
					}
					if err != nil {
						return fmt.Errorf("%s: %w", strings.TrimPrefix(key, p), err)
					}
				}
				after = others[len(others)-1]
			}
		}
		errs := make(chan error, pods+1)
		for _, s := range stores {
			go func() { errs <- walk(s) }()
		}
		// A pod that serves writes records the walk is about to seal again: its value stands.
		go func() {
			for round := range 3 {
				for i := range pods {
					key, value := fmt.Sprintf("%ssession:before:%d", p, i), fmt.Sprintf("written during the walk, round %d", round)
					if err := stores[(i+round)%pods].Set(ctx, key, []byte(value), time.Hour); err != nil {
						errs <- err
						return
					}
					hold(key, value)
				}
			}
			errs <- nil
		}()
		for range pods + 1 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		for i := range renamed {
			from, to := fmt.Sprintf("%sname-of-before:%d", p, i), fmt.Sprintf("%sname:%d", p, i)
			hold(to, held[from])
			delete(held, from)
		}
		for i, s := range stores {
			resealer := s.(kv.Resealer)
			if n, err := resealer.CountOthers(ctx, p); err != nil || n != 0 {
				others, _ := resealer.Others(ctx, p, "", 100)
				t.Errorf("pod %d counts %d records that are not under the key of now: %v, err %v", i, n, others, err)
			}
			if by := sealedBy(t, s); len(by) != 1 || by[newID] != len(held) {
				t.Errorf("pod %d: sealed by %v, of %d records", i, by, len(held))
			}
		}
		stored, err := raws[0].Keys(ctx, p)
		if want := slices.Sorted(maps.Keys(held)); err != nil || !slices.Equal(stored, want) {
			t.Errorf("the records after the walk: %d, of %d: err %v", len(stored), len(want), err)
		}
		serve(t, "after the walk", stores)
	})

	t.Run("the database lets go of a record that was sealed again when its time is over", func(t *testing.T) {
		brief := 5 * expiry
		if err := rollout(stages.known)[0].Set(ctx, p+"brief", []byte("ends soon"), brief); err != nil {
			t.Fatal(err)
		}
		if resealed, err := rollout(stages.sealing)[1].(kv.Resealer).Reseal(ctx, p+"brief"); err != nil || !resealed {
			t.Fatalf("resealed %v, err %v", resealed, err)
		}
		time.Sleep(brief + settle)
		if _, found, err := raws[2].Get(ctx, p+"brief"); err != nil || found {
			t.Errorf("the database still holds the record after its time: found %v, err %v", found, err)
		}
	})

	t.Run("once nothing is sealed under the old key it goes, and pods with and without it read every record", func(t *testing.T) {
		serve(t, "while the old key goes", rollout(stages.sealing, stages.alone))
		serve(t, "alone", rollout(stages.alone))
	})

	t.Run("a record that was sealed again or moved ends when it would have, not later", func(t *testing.T) {
		// The clock of the seals stood still until now, so every record of an hour ends at the same moment,
		// whenever it was written, sealed again or moved.
		reader := rollout(stages.alone)[pods-1]
		for _, step := range []struct {
			by     time.Duration
			ending bool
		}{{59 * time.Minute, true}, {2 * time.Minute, false}} {
			at.advance(step.by)
			for key := range held {
				_, found, err := reader.Get(ctx, key)
				if want := step.ending || strings.HasPrefix(key, p+"registration:"); err != nil || found != want {
					t.Errorf("%s, the clock advanced by %v: found %v, err %v", strings.TrimPrefix(key, p), step.by, found, err)
				}
			}
		}
	})
}

// follower is a follower of a topic that keeps its cursor, as a host does.
type follower struct {
	events <-chan kv.Event
	cancel context.CancelFunc
	cursor kv.Cursor
}

// follow starts a follower of topic on feed after the cursor from. It follows until t ends, which is the
// whole test where a follower outlives the subtest that starts it.
func follow(t *testing.T, feed kv.Feed, topic string, from kv.Cursor) *follower {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	events, err := feed.Follow(ctx, topic, from)
	if err != nil {
		t.Fatal(err)
	}
	return &follower{events: events, cancel: cancel, cursor: from}
}

// next takes the next event, which has to have the number after the cursor.
func (f *follower) next(t *testing.T) kv.Event {
	t.Helper()
	e := next(t, f.events)
	if e.Cursor != f.cursor+1 {
		t.Fatalf("after event %d came event %d", f.cursor, e.Cursor)
	}
	f.cursor = e.Cursor
	return e
}

// stop ends the follower and returns the cursor it restarts from.
func (f *follower) stop() kv.Cursor {
	f.cancel()
	return f.cursor
}

// SealedEvents publishes sealed events across a change of the feed's keys (server rules 5 and 22): a
// sealed store seals the events of its transactions under keys of their own (kv.WithSealedEvents), and a
// program that only follows holds those keys and none that opens a record (kv.NewSealedFeed). The follower
// restarts with each stage's file and takes up at its cursor; one that no longer holds the old key sees
// the events sealed under it as a gap.
func SealedEvents(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	const records, feedPurpose = "kvtest records", "kvtest revocations"
	raws := openPods(t, open, 2, Pod{Mark: kv.SealedMarker(nil)})
	p := prefix(t, raws[0])
	recordKeys, feedKeys := ring(t, "r"), keyStages{old: ring(t, "f"), known: ring(t, "f", "g"), sealing: ring(t, "g", "f"), alone: ring(t, "g")}
	a := topic("revocations")
	published := 0
	// revoke is a pod whose file for the feed is keys: it writes the revocation and publishes it, in one
	// transaction.
	revoke := func(keys kv.Keys) string {
		t.Helper()
		published++
		sid := fmt.Sprintf("session-of-Erika-Mustermann-%d", published)
		store := kv.NewSealed(raws[0], recordKeys, records, kv.WithSealedEvents(keys, feedPurpose))
		if err := inTx(ctx, store, func(tx kv.Tx) error {
			if err := tx.Set(ctx, p+"revoked:"+sid, []byte(sid), time.Hour); err != nil {
				return err
			}
			return tx.Publish(ctx, a, []byte(sid), time.Minute)
		}); err != nil {
			t.Fatal(err)
		}
		return sid
	}
	program := func(keys kv.Keys) kv.Feed { return kv.NewSealedFeed(raws[1].(kv.Feed), keys, feedPurpose) }
	whole := t
	expect := func(t *testing.T, f *follower, sid string) {
		t.Helper()
		if e := f.next(t); string(e.Payload) != sid {
			t.Fatalf("event %d: %q, want %q", e.Cursor, e.Payload, sid)
		}
	}

	following := follow(t, program(feedKeys.old), a, 0)
	first, second := revoke(feedKeys.old), revoke(feedKeys.old)
	expect(t, following, first)
	expect(t, following, second)

	t.Run("the database holds no event in the clear, the follower's keys open no record, and the records' keys no event", func(t *testing.T) {
		below := follow(t, raws[1].(kv.Feed), a, 0)
		for range 2 {
			if e := below.next(t); bytes.Contains(e.Payload, []byte("Mustermann")) {
				t.Errorf("the database holds event %d in the clear", e.Cursor)
			}
		}
		if err := failsClosed(kv.NewSealed(raws[1], feedKeys.old, records).Get(ctx, p+"revoked:"+first)); err != nil {
			t.Errorf("a record under the keys of the feed: %v", err)
		}
		none(t, follow(t, kv.NewSealedFeed(raws[1].(kv.Feed), recordKeys, feedPurpose), a, 0).events)
		none(t, follow(t, kv.NewSealed(raws[1], recordKeys, records).(kv.Feed), a, 0).events)
	})

	t.Run("the follower restarts with each stage's file and takes up at its cursor", func(t *testing.T) {
		following = follow(whole, program(feedKeys.known), a, following.stop())
		expect(t, following, revoke(feedKeys.known))
		// The publishers roll out before the followers: the new key seals while this follower's file is
		// still the one of the stage before.
		expect(t, following, revoke(feedKeys.sealing))
		expect(t, following, revoke(feedKeys.known))
		following = follow(whole, program(feedKeys.sealing), a, following.stop())
		expect(t, following, revoke(feedKeys.sealing))
		none(t, following.events)
	})

	t.Run("a follower that lost the old key sees the events sealed under it as a gap", func(t *testing.T) {
		alone := follow(t, program(feedKeys.alone), a, 0)
		for _, number := range []kv.Cursor{4, 6} {
			if e := next(t, alone.events); e.Cursor != number {
				t.Fatalf("event %d came, want %d: 1, 2, 3 and 5 are sealed under the old key", e.Cursor, number)
			}
		}
		following = follow(whole, program(feedKeys.alone), a, following.stop())
		expect(t, following, revoke(feedKeys.alone))
	})
}

// Revocations runs what an authorization server does with a revocation over several pods (server rule
// 11): one pod deletes the session, writes the revocation and publishes it in one transaction, and the
// followers of the other pods get it, in order and after the change it tells of. A follower that
// restarts takes up at its cursor; one that was away for longer than the events were kept sees the gap
// and reads its state anew from the records.
func Revocations(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	const purpose = "kvtest revocations"
	raws := openPods(t, open, 3, Pod{Mark: kv.SealedMarker(nil)})
	p := prefix(t, raws[0])
	keys := ring(t, "a")
	pods := make([]kv.Store, len(raws))
	for i, raw := range raws {
		pods[i] = kv.NewSealed(raw, keys, purpose, kv.WithSealedExpiry(time.Now))
	}
	a := topic("revocations")
	sessions := 0
	// revoke has a pod end a session: the record goes, the revocation is written and published.
	revoke := func(pod kv.Store, retention time.Duration, end error) string {
		t.Helper()
		sessions++
		sid := fmt.Sprintf("s%d", sessions)
		if err := pod.Set(ctx, p+"session:"+sid, []byte("the session "+sid), time.Hour); err != nil {
			t.Fatal(err)
		}
		err := inTx(ctx, pod, func(tx kv.Tx) error {
			if _, found, err := tx.Take(ctx, p+"session:"+sid); err != nil || !found {
				return errors.Join(fmt.Errorf("the session to revoke: found %v", found), err)
			}
			if err := tx.Set(ctx, p+"revoked:"+sid, []byte(sid), time.Hour); err != nil {
				return err
			}
			if err := tx.Publish(ctx, a, []byte(sid), retention); err != nil {
				return err
			}
			return end
		})
		if !errors.Is(err, end) {
			t.Fatalf("revoking %s: %v", sid, err)
		}
		return sid
	}
	// hears has a follower take its next event, which has to tell of a change its pod already sees.
	whole := t
	hears := func(t *testing.T, f *follower, pod kv.Store, sid string) {
		t.Helper()
		if e := f.next(t); string(e.Payload) != sid {
			t.Fatalf("event %d: %q, want %q", e.Cursor, e.Payload, sid)
		}
		if _, found, err := pod.Get(ctx, p+"session:"+sid); err != nil || found {
			t.Errorf("the follower heard of %s while its pod still finds the session: found %v, err %v", sid, found, err)
		}
		if _, found, err := pod.Get(ctx, p+"revoked:"+sid); err != nil || !found {
			t.Errorf("the follower heard of %s while its pod does not find the revocation: found %v, err %v", sid, found, err)
		}
	}
	followers := []*follower{nil, follow(t, pods[1].(kv.Feed), a, 0), follow(t, pods[2].(kv.Feed), a, 0)}

	t.Run("a revocation by one pod reaches the followers of the others, in order, after the change it tells of", func(t *testing.T) {
		for i := range 9 {
			sid := revoke(pods[i%3], time.Minute, nil)
			hears(t, followers[1], pods[1], sid)
			hears(t, followers[2], pods[2], sid)
		}
	})

	t.Run("a transaction that fails publishes nothing and takes no number", func(t *testing.T) {
		failed := errors.New("the operation failed")
		sid := revoke(pods[0], time.Minute, failed)
		if _, found, err := pods[1].Get(ctx, p+"session:"+sid); err != nil || !found {
			t.Errorf("the session of the failed revocation: found %v, err %v", found, err)
		}
		none(t, followers[1].events)
		sid = revoke(pods[0], time.Minute, nil)
		hears(t, followers[1], pods[1], sid)
		hears(t, followers[2], pods[2], sid)
	})

	t.Run("a follower whose pod restarts takes up at its cursor: no event twice, none missed", func(t *testing.T) {
		cursor := followers[1].stop()
		if err := raws[1].Close(); err != nil {
			t.Fatal(err)
		}
		var missed []string
		for range 3 {
			missed = append(missed, revoke(pods[0], time.Minute, nil))
		}
		raw, err := open(Pod{Number: 1, Mark: kv.SealedMarker(nil)})
		if err != nil {
			t.Fatal(err)
		}
		whole.Cleanup(func() { _ = raw.Close() })
		raws[1], pods[1] = raw, kv.NewSealed(raw, keys, purpose, kv.WithSealedExpiry(time.Now))
		followers[1] = follow(whole, pods[1].(kv.Feed), a, cursor)
		for _, sid := range append(missed, revoke(pods[2], time.Minute, nil)) {
			hears(t, followers[1], pods[1], sid)
			hears(t, followers[2], pods[2], sid)
		}
		none(t, followers[1].events)
	})

	t.Run("a follower that was away for longer than the events were kept sees the gap and finds every revocation in the records", func(t *testing.T) {
		cursor := followers[2].stop()
		gone := []string{revoke(pods[0], expiry, nil), revoke(pods[1], expiry, nil)}
		time.Sleep(settle)
		if _, err := pods[0].Cleanup(ctx); err != nil {
			t.Fatal(err)
		}
		kept := revoke(pods[0], time.Minute, nil)
		back := follow(t, pods[2].(kv.Feed), a, cursor)
		e := next(t, back.events)
		if e.Cursor != cursor+3 || string(e.Payload) != kept {
			t.Fatalf("after event %d came event %d, %q: the two before it were kept for %v", cursor, e.Cursor, e.Payload, expiry)
		}
		if latest, err := pods[2].(kv.Feed).Latest(ctx, a); err != nil || latest != e.Cursor {
			t.Errorf("latest %d, err %v", latest, err)
		}
		for _, sid := range gone {
			if got, found, err := pods[2].Get(ctx, p+"revoked:"+sid); err != nil || !found || string(got) != sid {
				t.Errorf("the revocation of %s in the records: %q, found %v, err %v", sid, got, found, err)
			}
		}
		revoked, err := pods[2].Keys(ctx, p+"revoked:")
		if err != nil || len(revoked) != int(e.Cursor) {
			t.Errorf("%d revocations are in the records, of %d that were published: %v", len(revoked), e.Cursor, err)
		}
	})
}

// Logins runs the worked case of the guide for hosts over several pods at once (server rule 11): each
// login of a user's new client reads the user's record first and writes it last, and makes room by
// removing the client that was away longest, with its session and a revocation of it. Whatever pods the
// logins of one user come through, none is lost, the index lists exactly the clients there are, and
// exactly the sessions that went were revoked.
func Logins(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	const purpose = "kvtest logins"
	const limit, perPod = 3, 4
	users := []string{"erika", "max"}
	raws := openPods(t, open, 3, Pod{Mark: kv.SealedMarker(nil)})
	p := prefix(t, raws[0])
	keys := ring(t, "a")
	pods := make([]kv.Store, len(raws))
	for i, raw := range raws {
		pods[i] = kv.NewSealed(raw, keys, purpose, kv.WithSealedExpiry(time.Now))
	}
	a := topic("revocations")
	var seen, runs atomic.Int64
	login := func(pod kv.Store, user, client string) error {
		at := seen.Add(1)
		return inTx(ctx, pod, func(tx kv.Tx) error {
			runs.Add(1)
			root, _, err := tx.Get(ctx, p+"user:"+user)
			if err != nil {
				return err
			}
			index, _, err := tx.Get(ctx, p+"clients:"+user)
			if err != nil {
				return err
			}
			clients := map[string]int64{}
			if len(index) > 0 {
				if err := json.Unmarshal(index, &clients); err != nil {
					return err
				}
			}
			for len(clients) >= limit {
				oldest := ""
				for name, last := range clients {
					if oldest == "" || last < clients[oldest] {
						oldest = name
					}
				}
				record, found, err := tx.Get(ctx, p+"client:"+user+":"+oldest)
				if err != nil || !found {
					return errors.Join(fmt.Errorf("the client %s of the index: found %v", oldest, found), err)
				}
				for sid := range strings.FieldsSeq(string(record)) {
					if err := tx.Delete(ctx, p+"session:"+user+":"+sid); err != nil {
						return err
					}
					if err := tx.Publish(ctx, a, []byte(user+":"+sid), time.Minute); err != nil {
						return err
					}
				}
				if err := tx.Delete(ctx, p+"client:"+user+":"+oldest); err != nil {
					return err
				}
				delete(clients, oldest)
			}
			clients[client] = at
			sid := "session-of-" + client
			if err := tx.Set(ctx, p+"client:"+user+":"+client, []byte(sid), time.Hour); err != nil {
				return err
			}
			if err := tx.Set(ctx, p+"session:"+user+":"+sid, []byte(client), time.Hour); err != nil {
				return err
			}
			index, err = json.Marshal(clients)
			if err != nil {
				return err
			}
			if err := tx.Set(ctx, p+"clients:"+user, index, time.Hour); err != nil {
				return err
			}
			logins, _ := strconv.Atoi(string(root))
			return tx.Set(ctx, p+"user:"+user, []byte(strconv.Itoa(logins+1)), time.Hour)
		})
	}

	following := follow(t, pods[1].(kv.Feed), a, 0)
	var wg sync.WaitGroup
	errs := make(chan error, len(users)*len(pods)*perPod)
	for _, user := range users {
		for i, pod := range pods {
			wg.Go(func() {
				for n := range perPod {
					if err := login(pod, user, fmt.Sprintf("client-%d-%d", i, n)); err != nil {
						errs <- fmt.Errorf("a login of %s through pod %d: %w", user, i, err)
					}
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	logins := len(pods) * perPod
	t.Logf("%d logins ran as %d transactions", len(users)*logins, runs.Load())

	revoked := map[string]bool{}
	for range len(users) * (logins - limit) {
		e := following.next(t)
		if revoked[string(e.Payload)] {
			t.Errorf("event %d revokes %s a second time", e.Cursor, e.Payload)
		}
		revoked[string(e.Payload)] = true
	}
	none(t, following.events)
	reader := pods[2]
	for _, user := range users {
		if root, _, err := reader.Get(ctx, p+"user:"+user); err != nil || string(root) != strconv.Itoa(logins) {
			t.Errorf("%s: the root counts %q logins, of %d: %v", user, root, logins, err)
		}
		index, _, err := reader.Get(ctx, p+"clients:"+user)
		if err != nil {
			t.Fatal(err)
		}
		clients := map[string]int64{}
		if err := json.Unmarshal(index, &clients); err != nil || len(clients) != limit {
			t.Fatalf("%s: the index lists %d clients, with room for %d: %v", user, len(clients), limit, err)
		}
		var wantClients, wantSessions []string
		for client := range clients {
			wantClients = append(wantClients, p+"client:"+user+":"+client)
			wantSessions = append(wantSessions, p+"session:"+user+":session-of-"+client)
		}
		sort.Strings(wantClients)
		sort.Strings(wantSessions)
		if got, err := reader.Keys(ctx, p+"client:"+user+":"); err != nil || !slices.Equal(got, wantClients) {
			t.Errorf("%s: the records of clients are not the clients of the index: %d records, err %v", user, len(got), err)
		}
		got, err := reader.Keys(ctx, p+"session:"+user+":")
		if err != nil || !slices.Equal(got, wantSessions) {
			t.Errorf("%s: the sessions are not those of the clients of the index: %d records, err %v", user, len(got), err)
		}
		for i := range pods {
			for n := range perPod {
				sid := fmt.Sprintf("%s:session-of-client-%d-%d", user, i, n)
				if there := slices.Contains(got, p+"session:"+sid); there == revoked[sid] {
					t.Errorf("the session %s: there %v, revoked %v", sid, there, revoked[sid])
				}
			}
		}
	}
}
