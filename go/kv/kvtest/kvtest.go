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
	"fmt"
	"slices"
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
		if err := s.Set(ctx, p+"gone", []byte("v"), expiry); err != nil {
			t.Fatal(err)
		}
		if err := s.Set(ctx, p+"stays", []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(settle)
		if removed, err := s.Cleanup(ctx); err != nil || removed < 1 {
			t.Fatalf("removed %d, err %v", removed, err)
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
