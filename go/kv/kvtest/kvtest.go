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

// Package kvtest is the contract of a kv backend as tests: what every store, in memory or in a database,
// does alike. A backend's own tests call [Store] and [Marker] with a function that opens it; a backend that
// passes can stand in for another behind kv.Store. It is test code: no package that is built into a program
// imports it (server rule 17).
package kvtest

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// expiry is the TTL of records the suite lets expire, and settle how long it waits for that. They are long
// enough for a database on another host, whose clock decides.
const (
	expiry = 300 * time.Millisecond
	settle = 600 * time.Millisecond
)

// concurrent is how many callers race for one record.
const concurrent = 16

var serial atomic.Int64

// prefix is a namespace of its own for one test, so that a store shared with other tests and other runs
// does not disturb it. What the test wrote is deleted afterwards.
func prefix(t *testing.T, s kv.Store) string {
	t.Helper()
	p := fmt.Sprintf("kvtest:%d:%d:", time.Now().UnixNano(), serial.Add(1))
	t.Cleanup(func() {
		ctx := context.Background()
		keys, _ := s.Keys(ctx, p)
		for _, k := range keys {
			_ = s.Delete(ctx, k)
		}
	})
	return p
}

// Store runs the contract of kv.Store, and of kv.Swapper, against the store open returns. open is called
// once per test and the store closed after it.
func Store(t *testing.T, open func(t *testing.T) kv.Store) {
	t.Helper()
	ctx := context.Background()
	run := func(name string, test func(t *testing.T, s kv.Store, p string)) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })
			test(t, s, prefix(t, s))
		})
	}

	run("a value is read as written until it is deleted", func(t *testing.T, s kv.Store, p string) {
		if _, found, err := s.Get(ctx, p+"a"); err != nil || found {
			t.Fatalf("absent key: found %v, err %v", found, err)
		}
		value := []byte{0, 1, 2, 0xff, '{', '"'}
		if err := s.Set(ctx, p+"a", value, 0); err != nil {
			t.Fatal(err)
		}
		if got, found, err := s.Get(ctx, p+"a"); err != nil || !found || !bytes.Equal(got, value) {
			t.Fatalf("got %v, found %v, err %v", got, found, err)
		}
		if err := s.Set(ctx, p+"a", []byte("second"), 0); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := s.Get(ctx, p+"a"); string(got) != "second" {
			t.Fatalf("after overwriting: %q", got)
		}
		if err := s.Delete(ctx, p+"a"); err != nil {
			t.Fatal(err)
		}
		if _, found, _ := s.Get(ctx, p+"a"); found {
			t.Fatal("found after delete")
		}
		if err := s.Delete(ctx, p+"a"); err != nil {
			t.Fatalf("deleting what is not there: %v", err)
		}
	})

	run("keys are listed by a literal prefix, sorted", func(t *testing.T, s kv.Store, p string) {
		for _, k := range []string{"b:2", "b:1", "c:1", "b%1", "b_1", `b\1`} {
			if err := s.Set(ctx, p+k, []byte("v"), 0); err != nil {
				t.Fatal(err)
			}
		}
		for prefix, want := range map[string][]string{
			"b:":  {p + "b:1", p + "b:2"},
			"b%":  {p + "b%1"},
			"b_":  {p + "b_1"},
			`b\`:  {p + `b\1`},
			"zzz": nil,
		} {
			got, err := s.Keys(ctx, p+prefix)
			if err != nil || !slices.Equal(got, want) {
				t.Errorf("prefix %q: got %v, want %v, err %v", prefix, got, want, err)
			}
		}
	})

	run("keys are in the order of their bytes, whatever a language would say", func(t *testing.T, s kv.Store, p string) {
		// By their bytes: B (0x42), Z (0x5a), a (0x61), ä (0xc3 0xa4). A dictionary has a, ä, B, Z.
		want := []string{p + "B", p + "Z", p + "a", p + "ä"}
		for _, k := range []string{p + "ä", p + "a", p + "Z", p + "B"} {
			if err := s.Set(ctx, k, []byte("v"), 0); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := s.Keys(ctx, p); err != nil || !slices.Equal(got, want) {
			t.Errorf("got %q, want %q, err %v", got, want, err)
		}
	})

	run("an empty value is a value", func(t *testing.T, s kv.Store, p string) {
		if err := s.Set(ctx, p+"empty", nil, 0); err != nil {
			t.Fatal(err)
		}
		if got, found, err := s.Get(ctx, p+"empty"); err != nil || !found || len(got) != 0 {
			t.Errorf("got %v, found %v, err %v", got, found, err)
		}
		if got, found, err := s.Take(ctx, p+"empty"); err != nil || !found || len(got) != 0 {
			t.Errorf("taken %v, found %v, err %v", got, found, err)
		}
	})

	run("a record with a TTL ends, for Get, Take and Keys", func(t *testing.T, s kv.Store, p string) {
		for _, k := range []string{"get", "take", "keys"} {
			if err := s.Set(ctx, p+k, []byte("v"), expiry); err != nil {
				t.Fatal(err)
			}
		}
		if _, found, _ := s.Get(ctx, p+"get"); !found {
			t.Fatal("gone before its time")
		}
		time.Sleep(settle)
		if _, found, err := s.Get(ctx, p+"get"); err != nil || found {
			t.Errorf("Get after expiry: found %v, err %v", found, err)
		}
		if _, found, err := s.Take(ctx, p+"take"); err != nil || found {
			t.Errorf("Take after expiry: found %v, err %v", found, err)
		}
		if keys, err := s.Keys(ctx, p); err != nil || len(keys) != 0 {
			t.Errorf("Keys after expiry: %v, err %v", keys, err)
		}
	})

	run("Take hands a value to exactly one of many", func(t *testing.T, s kv.Store, p string) {
		if err := s.Set(ctx, p+"code", []byte("once"), 0); err != nil {
			t.Fatal(err)
		}
		if won := race(t, func() (bool, error) {
			v, found, err := s.Take(ctx, p+"code")
			return found && string(v) == "once", err
		}); won != 1 {
			t.Fatalf("%d callers took the value", won)
		}
	})

	run("SetIfAbsent has exactly one winner among many", func(t *testing.T, s kv.Store, p string) {
		var n atomic.Int64
		if won := race(t, func() (bool, error) {
			return s.SetIfAbsent(ctx, p+"seen", fmt.Append(nil, n.Add(1)), time.Minute)
		}); won != 1 {
			t.Fatalf("%d callers set the value", won)
		}
	})

	run("SetIfAbsent leaves a standing record and replaces an expired one", func(t *testing.T, s kv.Store, p string) {
		if set, err := s.SetIfAbsent(ctx, p+"k", []byte("first"), expiry); err != nil || !set {
			t.Fatalf("first: set %v, err %v", set, err)
		}
		if set, err := s.SetIfAbsent(ctx, p+"k", []byte("second"), expiry); err != nil || set {
			t.Fatalf("second while the first stands: set %v, err %v", set, err)
		}
		if got, _, _ := s.Get(ctx, p+"k"); string(got) != "first" {
			t.Fatalf("the standing record was changed to %q", got)
		}
		time.Sleep(settle)
		if set, err := s.SetIfAbsent(ctx, p+"k", []byte("third"), 0); err != nil || !set {
			t.Fatalf("after expiry: set %v, err %v", set, err)
		}
		time.Sleep(settle)
		if got, found, _ := s.Get(ctx, p+"k"); !found || string(got) != "third" {
			t.Fatalf("a record without a TTL: found %v, %q", found, got)
		}
	})

	run("SetMany writes all its entries", func(t *testing.T, s kv.Store, p string) {
		if err := s.SetMany(ctx,
			kv.Entry{Key: p + "record", Value: []byte("r")},
			kv.Entry{Key: p + "index", Value: []byte("i"), TTL: time.Minute},
		); err != nil {
			t.Fatal(err)
		}
		for k, want := range map[string]string{"record": "r", "index": "i"} {
			if got, found, err := s.Get(ctx, p+k); err != nil || !found || string(got) != want {
				t.Errorf("%s: %q, found %v, err %v", k, got, found, err)
			}
		}
		if err := s.SetMany(ctx); err != nil {
			t.Errorf("no entries: %v", err)
		}
	})

	run("Cleanup removes what has expired and nothing else", func(t *testing.T, s kv.Store, p string) {
		const gone = 5
		for i := range gone {
			if err := s.Set(ctx, fmt.Sprintf("%sgone:%d", p, i), []byte("v"), expiry); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Set(ctx, p+"stays", []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(settle)
		if removed, err := s.Cleanup(ctx); err != nil || removed < gone {
			t.Fatalf("removed %d, err %v", removed, err)
		}
		// A read hides an expired record whether it is there or not: only a second Cleanup that does not
		// count them again shows that the first one took them out. On a shared database it may find what
		// others let expire since, but not all of these again.
		if again, err := s.Cleanup(ctx); err != nil || again >= gone {
			t.Fatalf("a second Cleanup removed %d, err %v: the first did not take the expired records out", again, err)
		}
		if _, found, _ := s.Get(ctx, p+"stays"); !found {
			t.Fatal("a record without a TTL was removed")
		}
	})

	run("Swap replaces only the value that was read, for one of many", func(t *testing.T, s kv.Store, p string) {
		swapper, ok := s.(kv.Swapper)
		if !ok {
			t.Fatal("the store is no kv.Swapper")
		}
		if swapped, err := swapper.Swap(ctx, p+"absent", []byte("a"), []byte("b"), 0); err != nil || swapped {
			t.Fatalf("an absent key: swapped %v, err %v", swapped, err)
		}
		if err := s.Set(ctx, p+"k", []byte("read"), 0); err != nil {
			t.Fatal(err)
		}
		if swapped, err := swapper.Swap(ctx, p+"k", []byte("other"), []byte("x"), 0); err != nil || swapped {
			t.Fatalf("another value than the one standing: swapped %v, err %v", swapped, err)
		}
		var n atomic.Int64
		if won := race(t, func() (bool, error) {
			return swapper.Swap(ctx, p+"k", []byte("read"), fmt.Appendf(nil, "next-%d", n.Add(1)), 0)
		}); won != 1 {
			t.Fatalf("%d callers swapped the value", won)
		}
		if err := s.Set(ctx, p+"e", []byte("read"), expiry); err != nil {
			t.Fatal(err)
		}
		time.Sleep(settle)
		if swapped, err := swapper.Swap(ctx, p+"e", []byte("read"), []byte("x"), 0); err != nil || swapped {
			t.Fatalf("an expired record: swapped %v, err %v", swapped, err)
		}
	})
}

// race calls try from many goroutines at once and returns how many of them it reported true for.
func race(t *testing.T, try func() (bool, error)) int {
	t.Helper()
	var won atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, concurrent)
	for range concurrent {
		wg.Go(func() {
			<-start
			ok, err := try()
			if err != nil {
				errs <- err
				return
			}
			if ok {
				won.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	return int(won.Load())
}

// Marker runs the contract of kv.Marker against the store open returns for a mark function: the store
// keeps beside each record what the function says of it.
func Marker(t *testing.T, open func(t *testing.T, mark func(key string, value []byte) string) kv.Store) {
	t.Helper()
	ctx := context.Background()
	// The mark of a record is the first byte of its value; a value beginning with '-' has none.
	mark := func(_ string, value []byte) string {
		if len(value) == 0 || value[0] == '-' {
			return ""
		}
		return string(value[:1])
	}
	s := open(t, mark)
	t.Cleanup(func() { _ = s.Close() })
	marker, ok := s.(kv.Marker)
	if !ok {
		t.Fatal("the store is no kv.Marker")
	}
	p := prefix(t, s)
	for k, v := range map[string]string{"1": "a1", "2": "b2", "3": "a3", "4": "-4", "5": "b5"} {
		if err := s.Set(ctx, p+k, []byte(v), 0); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("records are counted by their mark", func(t *testing.T) {
		marks, err := marker.Marks(ctx, p)
		if err != nil || marks["a"] != 2 || marks["b"] != 2 || marks[""] != 1 || len(marks) != 3 {
			t.Fatalf("marks %v, err %v", marks, err)
		}
	})
	t.Run("the records of another mark or none are found in order, page by page", func(t *testing.T) {
		if n, err := marker.CountMarkedOther(ctx, p, "b"); err != nil || n != 3 {
			t.Fatalf("count %d, err %v", n, err)
		}
		first, err := marker.MarkedOther(ctx, p, "b", "", 2)
		if err != nil || !slices.Equal(first, []string{p + "1", p + "3"}) {
			t.Fatalf("first page %v, err %v", first, err)
		}
		rest, err := marker.MarkedOther(ctx, p, "b", first[len(first)-1], 2)
		if err != nil || !slices.Equal(rest, []string{p + "4"}) {
			t.Fatalf("second page %v, err %v", rest, err)
		}
	})
	t.Run("a record written again carries the mark of its new value", func(t *testing.T) {
		if err := s.Set(ctx, p+"1", []byte("b1"), 0); err != nil {
			t.Fatal(err)
		}
		if n, err := marker.CountMarkedOther(ctx, p, "b"); err != nil || n != 2 {
			t.Fatalf("count %d, err %v", n, err)
		}
	})
}

// wait is how long the suite waits for an event a backend has to deliver; backends that are asked, not
// told, deliver within their interval.
const wait = 10 * time.Second

// next takes the next event of a follower, or fails when none comes.
func next(t *testing.T, events <-chan kv.Event) kv.Event {
	t.Helper()
	select {
	case e, ok := <-events:
		if !ok {
			t.Fatal("the follower's channel was closed")
		}
		return e
	case <-time.After(wait):
		t.Fatal("no event came")
	}
	return kv.Event{}
}

// none fails when a follower gets an event within a moment.
func none(t *testing.T, events <-chan kv.Event) {
	t.Helper()
	select {
	case e, ok := <-events:
		if ok {
			t.Fatalf("an event came that should not have: number %d, %q", e.Cursor, e.Payload)
		}
	case <-time.After(settle):
	}
}

// topic is a topic of its own for one test.
func topic(name string) string {
	return fmt.Sprintf("kvtest-%d-%d-%s", time.Now().UnixNano(), serial.Add(1), name)
}

// Feed runs the contract of kv.Feed against the store open returns, which must be one.
func Feed(t *testing.T, open func(t *testing.T) kv.Store) {
	t.Helper()
	ctx := context.Background()
	run := func(name string, test func(t *testing.T, f kv.Feed)) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })
			f, ok := s.(kv.Feed)
			if !ok {
				t.Fatal("the store is no kv.Feed")
			}
			test(t, f)
		})
	}

	run("events come in order, numbered from one, and a follower takes up at its cursor", func(t *testing.T, f kv.Feed) {
		a, b := topic("a"), topic("b")
		if latest, err := f.Latest(ctx, a); err != nil || latest != 0 {
			t.Fatalf("a topic without events: latest %d, err %v", latest, err)
		}
		for i := 1; i <= 5; i++ {
			cursor, err := f.Publish(ctx, a, fmt.Append(nil, i), time.Minute)
			if err != nil || cursor != kv.Cursor(i) {
				t.Fatalf("event %d: cursor %d, err %v", i, cursor, err)
			}
		}
		if cursor, err := f.Publish(ctx, b, []byte("other"), time.Minute); err != nil || cursor != 1 {
			t.Fatalf("another topic counts for itself: cursor %d, err %v", cursor, err)
		}
		if latest, err := f.Latest(ctx, a); err != nil || latest != 5 {
			t.Fatalf("latest %d, err %v", latest, err)
		}
		follow, cancel := context.WithCancel(ctx)
		defer cancel()
		all, err := f.Follow(follow, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 5; i++ {
			if e := next(t, all); e.Cursor != kv.Cursor(i) || string(e.Payload) != strconv.Itoa(i) || e.At.IsZero() {
				t.Fatalf("event %d: number %d, %q, at %v", i, e.Cursor, e.Payload, e.At)
			}
		}
		rest, err := f.Follow(follow, a, 3)
		if err != nil {
			t.Fatal(err)
		}
		for i := 4; i <= 5; i++ {
			if e := next(t, rest); e.Cursor != kv.Cursor(i) {
				t.Fatalf("after cursor 3: number %d, want %d", e.Cursor, i)
			}
		}
		none(t, rest)
	})

	run("a follower gets what is published after it began, and its channel closes when it ends", func(t *testing.T, f kv.Feed) {
		a := topic("live")
		follow, cancel := context.WithCancel(ctx)
		events, err := f.Follow(follow, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		none(t, events)
		if _, err := f.Publish(ctx, a, []byte("first"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if e := next(t, events); e.Cursor != 1 || string(e.Payload) != "first" {
			t.Fatalf("number %d, %q", e.Cursor, e.Payload)
		}
		cancel()
		select {
		case _, ok := <-events:
			if ok {
				t.Fatal("an event came after the follower ended")
			}
		case <-time.After(wait):
			t.Fatal("the channel was not closed")
		}
	})

	run("of many that publish at once no event is stepped over", func(t *testing.T, f kv.Feed) {
		a := topic("many")
		const each = 10
		follow, cancel := context.WithCancel(ctx)
		defer cancel()
		events, err := f.Follow(follow, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, concurrent*each)
		for p := range concurrent {
			wg.Go(func() {
				for i := range each {
					if _, err := f.Publish(ctx, a, fmt.Appendf(nil, "%d-%d", p, i), time.Minute); err != nil {
						errs <- err
					}
				}
			})
		}
		// The follower reads while they publish: an event that became visible after one with a higher
		// number would be stepped over.
		seen := map[string]bool{}
		for i := 1; i <= concurrent*each; i++ {
			e := next(t, events)
			if e.Cursor != kv.Cursor(i) {
				t.Fatalf("event %d has the number %d", i, e.Cursor)
			}
			seen[string(e.Payload)] = true
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if len(seen) != concurrent*each {
			t.Fatalf("%d different events came, of %d", len(seen), concurrent*each)
		}
		if latest, err := f.Latest(ctx, a); err != nil || latest != concurrent*each {
			t.Fatalf("latest %d, err %v", latest, err)
		}
	})

	run("an event is gone after its retention, and the gap shows in the numbers", func(t *testing.T, f kv.Feed) {
		a := topic("kept")
		if _, err := f.Publish(ctx, a, []byte("short"), expiry); err != nil {
			t.Fatal(err)
		}
		time.Sleep(settle)
		if _, err := f.Publish(ctx, a, []byte("long"), time.Minute); err != nil {
			t.Fatal(err)
		}
		follow, cancel := context.WithCancel(ctx)
		defer cancel()
		events, err := f.Follow(follow, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		if e := next(t, events); e.Cursor != 2 || string(e.Payload) != "long" {
			t.Fatalf("number %d, %q: the event whose retention is over was expected to be gone", e.Cursor, e.Payload)
		}
	})

	run("a topic or an event the feed does not take is refused", func(t *testing.T, f kv.Feed) {
		for name, publish := range map[string]func() (kv.Cursor, error){
			"no topic": func() (kv.Cursor, error) { return f.Publish(ctx, "", []byte("e"), time.Minute) },
			"too long topic": func() (kv.Cursor, error) {
				return f.Publish(ctx, strings.Repeat("t", kv.MaxTopicLen+1), []byte("e"), time.Minute)
			},
			"too long event": func() (kv.Cursor, error) {
				return f.Publish(ctx, topic("big"), make([]byte, kv.MaxEventLen+1), time.Minute)
			},
			"no retention": func() (kv.Cursor, error) { return f.Publish(ctx, topic("forever"), []byte("e"), 0) },
		} {
			if _, err := publish(); !errors.Is(err, kv.ErrEvent) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

// Tx runs the contract of kv.Transactor against the store open returns, which must be one and a kv.Feed.
func Tx(t *testing.T, open func(t *testing.T) kv.Store) {
	t.Helper()
	ctx := context.Background()
	run := func(name string, test func(t *testing.T, s kv.Store, tr kv.Transactor, p string)) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })
			tr, ok := s.(kv.Transactor)
			if !ok {
				t.Fatal("the store is no kv.Transactor")
			}
			test(t, s, tr, prefix(t, s))
		})
	}
	failed := errors.New("the operation failed")

	run("what a transaction writes and publishes takes effect together, or not at all", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		f := s.(kv.Feed)
		a := topic("tx")
		if err := s.Set(ctx, p+"standing", []byte("before"), 0); err != nil {
			t.Fatal(err)
		}
		write := func(end error) func(kv.Tx) error {
			return func(tx kv.Tx) error {
				if err := tx.Set(ctx, p+"record", []byte("r"), 0); err != nil {
					return err
				}
				if err := tx.Set(ctx, p+"standing", []byte("after"), 0); err != nil {
					return err
				}
				if err := tx.Delete(ctx, p+"absent"); err != nil {
					return err
				}
				if err := tx.Publish(ctx, a, []byte("changed"), time.Minute); err != nil {
					return err
				}
				return end
			}
		}
		if err := tr.Tx(ctx, write(failed)); !errors.Is(err, failed) {
			t.Fatalf("a transaction whose function fails returns %v", err)
		}
		if _, found, _ := s.Get(ctx, p+"record"); found {
			t.Error("a record of the failed transaction is there")
		}
		if got, _, _ := s.Get(ctx, p+"standing"); string(got) != "before" {
			t.Errorf("a record the failed transaction wrote over holds %q", got)
		}
		if latest, err := f.Latest(ctx, a); err != nil || latest != 0 {
			t.Errorf("the failed transaction's event: latest %d, err %v", latest, err)
		}
		if err := tr.Tx(ctx, write(nil)); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := s.Get(ctx, p+"record"); string(got) != "r" {
			t.Errorf("the record holds %q", got)
		}
		if got, _, _ := s.Get(ctx, p+"standing"); string(got) != "after" {
			t.Errorf("the record written over holds %q", got)
		}
		if latest, err := f.Latest(ctx, a); err != nil || latest != 1 {
			t.Errorf("the event of the transaction: latest %d, err %v", latest, err)
		}
	})

	run("a transaction reads what it wrote, and takes, sets if absent and deletes as the store does", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		if err := s.Set(ctx, p+"code", []byte("once"), 0); err != nil {
			t.Fatal(err)
		}
		err := tr.Tx(ctx, func(tx kv.Tx) error {
			if got, found, err := tx.Take(ctx, p+"code"); err != nil || !found || string(got) != "once" {
				return fmt.Errorf("take: %q, found %v, err %w", got, found, err)
			}
			if _, found, err := tx.Take(ctx, p+"code"); err != nil || found {
				return fmt.Errorf("take again: found %v, err %w", found, err)
			}
			if set, err := tx.SetIfAbsent(ctx, p+"new", []byte("first"), 0); err != nil || !set {
				return fmt.Errorf("set if absent: set %v, err %w", set, err)
			}
			if set, err := tx.SetIfAbsent(ctx, p+"new", []byte("second"), 0); err != nil || set {
				return fmt.Errorf("set if absent again: set %v, err %w", set, err)
			}
			if got, found, err := tx.Get(ctx, p+"new"); err != nil || !found || string(got) != "first" {
				return fmt.Errorf("get of its own write: %q, found %v, err %w", got, found, err)
			}
			if err := tx.Set(ctx, p+"gone", []byte("v"), 0); err != nil {
				return err
			}
			if err := tx.Delete(ctx, p+"gone"); err != nil {
				return err
			}
			if _, found, err := tx.Get(ctx, p+"gone"); err != nil || found {
				return fmt.Errorf("get of what it deleted: found %v, err %w", found, err)
			}
			return tx.Set(ctx, p+"short", []byte("v"), expiry)
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, found, _ := s.Get(ctx, p+"code"); found {
			t.Error("the taken record is still there")
		}
		if got, _, _ := s.Get(ctx, p+"new"); string(got) != "first" {
			t.Errorf("the record set if absent holds %q", got)
		}
		time.Sleep(settle)
		if _, found, _ := s.Get(ctx, p+"short"); found {
			t.Error("a record written with a TTL in a transaction did not end")
		}
	})

	run("a record a transaction read is not changed under it: of many that count one up, none is lost", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		if err := s.Set(ctx, p+"count", []byte("0"), 0); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, concurrent)
		for range concurrent {
			wg.Go(func() {
				if err := tr.Tx(ctx, func(tx kv.Tx) error {
					read, _, err := tx.Get(ctx, p+"count")
					if err != nil {
						return err
					}
					var n int
					if _, err := fmt.Sscan(string(read), &n); err != nil {
						return err
					}
					return tx.Set(ctx, p+"count", fmt.Append(nil, n+1), 0)
				}); err != nil {
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if got, _, _ := s.Get(ctx, p+"count"); string(got) != strconv.Itoa(concurrent) {
			t.Fatalf("%d transactions counted up to %q", concurrent, got)
		}
	})

	run("records under one root change together: the root is read first and written last", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		// Each transaction adds a member under the root and a record for it, if there is room for one more.
		// Without the root they would all find room at once.
		const room = 5
		var wg sync.WaitGroup
		errs := make(chan error, concurrent)
		for i := range concurrent {
			wg.Go(func() {
				if err := tr.Tx(ctx, func(tx kv.Tx) error {
					root, _, err := tx.Get(ctx, p+"root")
					if err != nil {
						return err
					}
					members := strings.Fields(string(root))
					if len(members) >= room {
						return nil
					}
					member := strconv.Itoa(i)
					if err := tx.Set(ctx, p+"member:"+member, []byte("m"), 0); err != nil {
						return err
					}
					return tx.Set(ctx, p+"root", []byte(strings.Join(append(members, member), " ")), 0)
				}); err != nil {
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		root, _, _ := s.Get(ctx, p+"root")
		members, _ := s.Keys(ctx, p+"member:")
		if len(strings.Fields(string(root))) != room || len(members) != room {
			t.Fatalf("the root lists %d members and %d records are there, with room for %d", len(strings.Fields(string(root))), len(members), room)
		}
	})

	run("a transaction that makes too many calls takes no effect", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		err := tr.Tx(ctx, func(tx kv.Tx) error {
			for i := range kv.MaxTxOps + 1 {
				if err := tx.Set(ctx, fmt.Sprintf("%s%d", p, i), []byte("v"), 0); err != nil {
					return err
				}
			}
			return nil
		})
		if !errors.Is(err, kv.ErrTxTooLarge) {
			t.Fatalf("got %v", err)
		}
		if keys, _ := s.Keys(ctx, p); len(keys) != 0 {
			t.Fatalf("%d records of it are there", len(keys))
		}
	})

	run("two transactions that wait for each other's records both take effect, whichever of them the database ends", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		// Each reads one record, waits until the other has read its own, and then reads the other's:
		// where both run at once, neither can go on, and the database ends one of them.
		held := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
		var once [2]sync.Once
		var runs atomic.Int64
		count := func(tx kv.Tx, key string) error {
			read, _, err := tx.Get(ctx, key)
			if err != nil {
				return err
			}
			n, _ := strconv.Atoi(string(read))
			return tx.Set(ctx, key, []byte(strconv.Itoa(n+1)), 0)
		}
		errs := make(chan error, 2)
		for i := range 2 {
			go func() {
				errs <- tr.Tx(ctx, func(tx kv.Tx) error {
					runs.Add(1)
					if err := count(tx, p+strconv.Itoa(i)); err != nil {
						return err
					}
					once[i].Do(func() { close(held[i]) })
					select {
					case <-held[1-i]:
					case <-time.After(settle):
					}
					return count(tx, p+strconv.Itoa(1-i))
				})
			}()
		}
		for range 2 {
			if err := <-errs; err != nil {
				t.Errorf("a transaction that met another: %v", err)
			}
		}
		for i := range 2 {
			if got, _, err := s.Get(ctx, p+strconv.Itoa(i)); err != nil || string(got) != "2" {
				t.Errorf("record %d was counted up to %q by two transactions: %v", i, got, err)
			}
		}
		t.Logf("the two transactions ran %d times", runs.Load())
	})

	run("an event a transaction may not publish fails it", func(t *testing.T, s kv.Store, tr kv.Transactor, p string) {
		err := tr.Tx(ctx, func(tx kv.Tx) error {
			if err := tx.Set(ctx, p+"record", []byte("r"), 0); err != nil {
				return err
			}
			return tx.Publish(ctx, "", []byte("e"), time.Minute)
		})
		if !errors.Is(err, kv.ErrEvent) {
			t.Fatalf("got %v", err)
		}
		if _, found, _ := s.Get(ctx, p+"record"); found {
			t.Error("the record of the failed transaction is there")
		}
	})
}

// TxOutside runs the part of the contract of kv.Transactor that is about callers outside a transaction,
// against the store open returns: what a transaction read with Get stays as read until its end, also
// against a call of the store itself by another caller, for a record that is there and for one that is
// not. It is for a store on one database node: across the writing nodes of a cluster a record a
// transaction only read is not protected, which the contract says.
func TxOutside(t *testing.T, open func(t *testing.T) kv.Store) {
	t.Helper()
	ctx := context.Background()
	for name, there := range map[string]bool{
		"a record a transaction read is not changed under it by a caller outside a transaction":         true,
		"a record a transaction found absent is not written under it by a caller outside a transaction": false,
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })
			tr, ok := s.(kv.Transactor)
			if !ok {
				t.Fatal("the store is no kv.Transactor")
			}
			key := prefix(t, s) + "decided-on"
			if there {
				if err := s.Set(ctx, key, []byte("before"), 0); err != nil {
					t.Fatal(err)
				}
			}
			outside := make(chan error, 1)
			var write sync.Once
			err := tr.Tx(ctx, func(tx kv.Tx) error {
				first, found, err := tx.Get(ctx, key)
				if err != nil {
					return err
				}
				if found != there {
					return fmt.Errorf("the transaction finds the record there: %v", found)
				}
				write.Do(func() {
					go func() { outside <- s.Set(ctx, key, []byte("outside"), 0) }()
				})
				// Long enough for the caller outside to write, if nothing holds it.
				time.Sleep(settle)
				again, found, err := tx.Get(ctx, key)
				if err != nil {
					return err
				}
				if found != there || !bytes.Equal(again, first) {
					return fmt.Errorf("what the transaction read changed under it: it read %q, there %v, and then %q, there %v", first, there, again, found)
				}
				return tx.Set(ctx, key, []byte("inside"), 0)
			})
			if err != nil {
				t.Error(err)
			}
			if err := <-outside; err != nil {
				t.Fatal(err)
			}
			// The caller outside waited for the transaction, so its value is the later one.
			if got, _, err := s.Get(ctx, key); err != nil || string(got) != "outside" {
				t.Errorf("after both, the record holds %q: %v", got, err)
			}
		})
	}
}

// Ephemeral runs what an ephemeral store does besides the contract of kv.Store, against the store open
// returns: it says its class, runs transactions over its records, and publishes no events.
func Ephemeral(t *testing.T, open func(t *testing.T) kv.Store) {
	t.Helper()
	ctx := context.Background()
	s := open(t)
	t.Cleanup(func() { _ = s.Close() })
	p := prefix(t, s)
	if got := kv.DurabilityOf(s); got != kv.Ephemeral {
		t.Fatalf("the store says it is %v", got)
	}
	tr, ok := s.(kv.Transactor)
	if !ok {
		t.Fatal("the store is no kv.Transactor")
	}

	t.Run("a transaction of ephemeral records takes effect, or not at all", func(t *testing.T) {
		failed := errors.New("the operation failed")
		write := func(end error) func(kv.Tx) error {
			return func(tx kv.Tx) error {
				if _, _, err := tx.Get(ctx, p+"root"); err != nil {
					return err
				}
				if err := tx.Set(ctx, p+"member", []byte("m"), time.Minute); err != nil {
					return err
				}
				if err := tx.Set(ctx, p+"root", []byte("member"), time.Minute); err != nil {
					return err
				}
				return end
			}
		}
		if err := tr.Tx(ctx, write(failed)); !errors.Is(err, failed) {
			t.Fatalf("got %v", err)
		}
		if keys, _ := s.Keys(ctx, p); len(keys) != 0 {
			t.Fatalf("records of the failed transaction are there: %v", keys)
		}
		if err := tr.Tx(ctx, write(nil)); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := s.Get(ctx, p+"root"); string(got) != "member" {
			t.Fatalf("the root holds %q", got)
		}
	})

	t.Run("events are not published: the feed is durable", func(t *testing.T) {
		err := tr.Tx(ctx, func(tx kv.Tx) error {
			if err := tx.Set(ctx, p+"with-event", []byte("v"), time.Minute); err != nil {
				return err
			}
			return tx.Publish(ctx, topic("ephemeral"), []byte("e"), time.Minute)
		})
		if !errors.Is(err, kv.ErrEphemeralEvent) {
			t.Fatalf("a transaction that publishes: %v", err)
		}
		if _, found, _ := s.Get(ctx, p+"with-event"); found {
			t.Error("the record of the refused transaction is there")
		}
		if f, ok := s.(kv.Feed); ok {
			if _, err := f.Publish(ctx, topic("ephemeral"), []byte("e"), time.Minute); !errors.Is(err, kv.ErrEphemeralEvent) {
				t.Errorf("Publish: %v", err)
			}
			if _, err := f.Follow(ctx, topic("ephemeral"), 0); !errors.Is(err, kv.ErrEphemeralEvent) {
				t.Errorf("Follow: %v", err)
			}
			if _, err := f.Latest(ctx, topic("ephemeral")); !errors.Is(err, kv.ErrEphemeralEvent) {
				t.Errorf("Latest: %v", err)
			}
		}
	})
}

// ring is a key ring of the given IDs, the first of them current. A key is its ID's first byte, repeated:
// the suite's keys protect nothing.
func ring(t *testing.T, ids ...string) *kv.Keyring {
	t.Helper()
	keys, err := parseRing(ids...)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func parseRing(ids ...string) (*kv.Keyring, error) {
	var lines strings.Builder
	for _, id := range ids {
		lines.WriteString(id + " " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{id[0]}, 32)) + "\n")
	}
	return kv.ParseKeyring([]byte(lines.String()))
}

// SealedFeed runs the contract of a sealed feed over the store open returns, which must be a kv.Feed that
// numbers its events (kv.NumberedFeed): the store below sees no payload, and an event opens only where and
// as what it was sealed.
func SealedFeed(t *testing.T, open func(t *testing.T) kv.Store) {
	t.Helper()
	ctx := context.Background()
	const secret = "the session of Erika Mustermann was revoked"
	run := func(name string, test func(t *testing.T, raw kv.Feed, sealed kv.Feed)) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })
			raw, ok := s.(kv.Feed)
			if !ok {
				t.Fatal("the store is no kv.Feed")
			}
			test(t, raw, kv.NewSealedFeed(raw, ring(t, "a"), "kvtest events"))
		})
	}
	follow := func(t *testing.T, f kv.Feed, topic string) <-chan kv.Event {
		t.Helper()
		ctx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		events, err := f.Follow(ctx, topic, 0)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}

	run("an event is read as published, and the feed below holds no payload", func(t *testing.T, raw, sealed kv.Feed) {
		a := topic("sealed")
		for i := 1; i <= 3; i++ {
			if cursor, err := sealed.Publish(ctx, a, fmt.Appendf(nil, "%s %d", secret, i), time.Minute); err != nil || cursor != kv.Cursor(i) {
				t.Fatalf("event %d: cursor %d, err %v", i, cursor, err)
			}
		}
		below, opened := follow(t, raw, a), follow(t, sealed, a)
		for i := 1; i <= 3; i++ {
			if e := next(t, below); bytes.Contains(e.Payload, []byte("Mustermann")) {
				t.Fatalf("the feed below holds event %d in the clear", e.Cursor)
			}
			if e := next(t, opened); e.Cursor != kv.Cursor(i) || string(e.Payload) != fmt.Sprintf("%s %d", secret, i) {
				t.Fatalf("event %d: number %d, %q", i, e.Cursor, e.Payload)
			}
		}
		if latest, err := sealed.Latest(ctx, a); err != nil || latest != 3 {
			t.Fatalf("latest %d, err %v", latest, err)
		}
	})

	run("an event put under another topic or another number does not open", func(t *testing.T, raw, sealed kv.Feed) {
		a, b := topic("from"), topic("to")
		if _, err := sealed.Publish(ctx, a, []byte(secret), time.Minute); err != nil {
			t.Fatal(err)
		}
		taken := next(t, follow(t, raw, a)).Payload
		// Whoever can write to the feed below copies the sealed event to another topic, and again to its
		// own topic, where it gets the next number.
		if _, err := raw.Publish(ctx, b, taken, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Publish(ctx, a, taken, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := sealed.Publish(ctx, a, []byte("after"), time.Minute); err != nil {
			t.Fatal(err)
		}
		none(t, follow(t, sealed, b))
		opened := follow(t, sealed, a)
		if e := next(t, opened); e.Cursor != 1 || string(e.Payload) != secret {
			t.Fatalf("the event in its place: number %d, %q", e.Cursor, e.Payload)
		}
		// Number 2 is the copy: it is left out, and the number that is missing shows it.
		if e := next(t, opened); e.Cursor != 3 || string(e.Payload) != "after" {
			t.Fatalf("after the copy: number %d, %q", e.Cursor, e.Payload)
		}
	})

	run("an event opens neither under another purpose nor under another key, and not when altered", func(t *testing.T, raw, sealed kv.Feed) {
		a := topic("purpose")
		if _, err := sealed.Publish(ctx, a, []byte(secret), time.Minute); err != nil {
			t.Fatal(err)
		}
		none(t, follow(t, kv.NewSealedFeed(raw, ring(t, "a"), "another purpose"), a))
		none(t, follow(t, kv.NewSealedFeed(raw, ring(t, "b"), "kvtest events"), a))
		// An event that was never sealed, and one with a bit of the sealed one changed.
		taken := next(t, follow(t, raw, a)).Payload
		altered := bytes.Clone(taken)
		altered[len(altered)-1] ^= 1
		for _, payload := range [][]byte{[]byte("made up"), altered, {}} {
			if _, err := raw.Publish(ctx, a, payload, time.Minute); err != nil {
				t.Fatal(err)
			}
		}
		opened := follow(t, sealed, a)
		if e := next(t, opened); e.Cursor != 1 {
			t.Fatalf("number %d", e.Cursor)
		}
		none(t, opened)
	})

	run("an event sealed under a key of before opens while the ring holds that key", func(t *testing.T, raw, _ kv.Feed) {
		a := topic("rotated")
		if _, err := kv.NewSealedFeed(raw, ring(t, "a"), "kvtest events").Publish(ctx, a, []byte("old key"), time.Minute); err != nil {
			t.Fatal(err)
		}
		rotated := kv.NewSealedFeed(raw, ring(t, "b", "a"), "kvtest events")
		if _, err := rotated.Publish(ctx, a, []byte("new key"), time.Minute); err != nil {
			t.Fatal(err)
		}
		opened := follow(t, rotated, a)
		for i, want := range []string{"old key", "new key"} {
			if e := next(t, opened); e.Cursor != kv.Cursor(i+1) || string(e.Payload) != want {
				t.Fatalf("event %d: number %d, %q", i+1, e.Cursor, e.Payload)
			}
		}
	})

	run("too long an event is refused before it is sealed", func(t *testing.T, _, sealed kv.Feed) {
		if _, err := sealed.Publish(ctx, topic("big"), make([]byte, kv.MaxEventLen), time.Minute); !errors.Is(err, kv.ErrEvent) {
			t.Fatalf("got %v", err)
		}
	})
}

// Resealer runs the contract of kv.Resealer, which a sealed store is over a store that keeps marks and
// swaps: after the keys changed, the records sealed under the key of before are found without reading
// every record, and taken along. open returns the store below for a mark function.
func Resealer(t *testing.T, open func(t *testing.T, mark func(key string, value []byte) string) kv.Store) {
	t.Helper()
	ctx := context.Background()
	raw := open(t, kv.SealedMarker(nil))
	t.Cleanup(func() { _ = raw.Close() })
	p := prefix(t, raw)
	before := kv.NewSealed(raw, ring(t, "a"), "kvtest records", kv.WithSealedExpiry(time.Now))
	for _, k := range []string{"1", "2", "3"} {
		if err := before.Set(ctx, p+k, []byte("of before "+k), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	store := kv.NewSealed(raw, ring(t, "b", "a"), "kvtest records", kv.WithSealedExpiry(time.Now))
	if err := store.Set(ctx, p+"4", []byte("of now"), time.Hour); err != nil {
		t.Fatal(err)
	}
	resealer, ok := store.(kv.Resealer)
	if !ok {
		t.Fatal("the sealed store is no kv.Resealer")
	}

	t.Run("the records of the key of before are counted and found, page by page", func(t *testing.T) {
		if by, err := resealer.SealedByKeys(ctx, p); err != nil || by["a"] != 3 || by["b"] != 1 || len(by) != 2 {
			t.Fatalf("sealed by %v, err %v", by, err)
		}
		if id, found, err := resealer.SealedBy(ctx, p+"1"); err != nil || !found || id != "a" {
			t.Fatalf("sealed by %q, found %v, err %v", id, found, err)
		}
		if n, err := resealer.CountOthers(ctx, p); err != nil || n != 3 {
			t.Fatalf("count %d, err %v", n, err)
		}
		first, err := resealer.Others(ctx, p, "", 2)
		if err != nil || !slices.Equal(first, []string{p + "1", p + "2"}) {
			t.Fatalf("first page %v, err %v", first, err)
		}
		rest, err := resealer.Others(ctx, p, first[len(first)-1], 2)
		if err != nil || !slices.Equal(rest, []string{p + "3"}) {
			t.Fatalf("second page %v, err %v", rest, err)
		}
	})

	t.Run("a record is sealed again under the key of now, once, with its value", func(t *testing.T) {
		if resealed, err := resealer.Reseal(ctx, p+"1"); err != nil || !resealed {
			t.Fatalf("resealed %v, err %v", resealed, err)
		}
		if resealed, err := resealer.Reseal(ctx, p+"1"); err != nil || resealed {
			t.Fatalf("again: resealed %v, err %v", resealed, err)
		}
		if resealed, err := resealer.Reseal(ctx, p+"4"); err != nil || resealed {
			t.Fatalf("a record of the key of now: resealed %v, err %v", resealed, err)
		}
		if id, _, err := resealer.SealedBy(ctx, p+"1"); err != nil || id != "b" {
			t.Fatalf("sealed by %q, err %v", id, err)
		}
		if got, found, err := store.Get(ctx, p+"1"); err != nil || !found || string(got) != "of before 1" {
			t.Fatalf("the value: %q, found %v, err %v", got, found, err)
		}
		if n, err := resealer.CountOthers(ctx, p); err != nil || n != 2 {
			t.Fatalf("count %d, err %v", n, err)
		}
	})

	t.Run("a record is moved to another key under the key of now, once", func(t *testing.T) {
		if moved, err := resealer.Rename(ctx, p+"2", p+"moved"); err != nil || !moved {
			t.Fatalf("moved %v, err %v", moved, err)
		}
		if got, found, err := store.Get(ctx, p+"moved"); err != nil || !found || string(got) != "of before 2" {
			t.Fatalf("under the new key: %q, found %v, err %v", got, found, err)
		}
		if _, found, _ := store.Get(ctx, p+"2"); found {
			t.Fatal("the record is still under the key of before")
		}
		if moved, err := resealer.Rename(ctx, p+"2", p+"moved"); err != nil || moved {
			t.Fatalf("again: moved %v, err %v", moved, err)
		}
		if by, err := resealer.SealedByKeys(ctx, p); err != nil || by["a"] != 1 || by["b"] != 3 {
			t.Fatalf("sealed by %v, err %v", by, err)
		}
	})
}
