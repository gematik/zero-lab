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

// Package storetest runs the corpus of spec/store (testdata/manifest.json) against
// package store and its backends: [Evaluate] answers one case, as the store-conformance
// adapter does; [RunCorpus] runs the cases as subtests, for the tests of this module and
// of backends in other modules.
package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/store"
)

// Obj is a case's input or output: byte strings in hex, integers below 2^53.
type Obj = map[string]any

// Backends makes a fresh backend of a name for a scenario, or nil if there is none.
type Backends func(name string) (store.Backend, func(), error)

// ErrUnsupported answers a kind or backend this implementation does not have.
var ErrUnsupported = errors.New("unsupported")

// errBadCase marks input that does not fit its kind: a broken case, not a verdict.
var errBadCase = errors.New("bad case")

type in struct{ o Obj }

func (i in) has(k string) bool { _, ok := i.o[k]; return ok }

func (i in) str(k string) (string, error) {
	s, ok := i.o[k].(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", errBadCase, k)
	}
	return s, nil
}

func (i in) bytes(k string) ([]byte, error) {
	s, err := i.str(k)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errBadCase, k)
	}
	return b, nil
}

func (i in) num(k string) (uint64, error) {
	switch v := i.o[k].(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%w: %s", errBadCase, k)
		}
		return uint64(n), nil
	case float64:
		return uint64(v), nil
	}
	return 0, fmt.Errorf("%w: %s", errBadCase, k)
}

func (i in) time(k string) (time.Time, error) {
	n, err := i.num(k)
	return store.FromWire(n), err
}

func (i in) list(k string) ([]in, error) {
	raw, ok := i.o[k]
	if !ok {
		return nil, nil
	}
	a, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errBadCase, k)
	}
	out := make([]in, 0, len(a))
	for _, x := range a {
		o, ok := x.(Obj)
		if !ok {
			return nil, fmt.Errorf("%w: %s", errBadCase, k)
		}
		out = append(out, in{o})
	}
	return out, nil
}

// tags reads tags; a field or tag outside its syntax is invalid_argument, as a backend
// would answer it.
func (i in) tags(k string) ([]store.Tag, error) {
	l, err := i.list(k)
	if err != nil {
		return nil, err
	}
	var out []store.Tag
	for _, t := range l {
		f, err := t.str("field")
		if err != nil {
			return nil, err
		}
		b, err := t.bytes("tag")
		if err != nil {
			return nil, err
		}
		if !store.ValidField(f) || len(b) != 32 {
			return nil, store.ErrInvalidArgument
		}
		out = append(out, store.Tag{Field: f, Tag: [32]byte(b)})
	}
	return out, nil
}

func h(b []byte) string { return hex.EncodeToString(b) }

func wire(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.Unix())
}

// Evaluate answers one case: the result code and, for ok, the output. An error is a broken
// case.
func Evaluate(kind string, input Obj, backends Backends) (store.Code, Obj, error) {
	out, err := answer(kind, in{input}, backends)
	switch {
	case errors.Is(err, errBadCase):
		return "", nil, err
	case errors.Is(err, ErrUnsupported):
		return "unsupported", nil, nil
	case err != nil:
		return store.CodeOf(err), nil, nil
	}
	return store.CodeOK, out, nil
}

func derive(b []byte) (store.DerivedKeys, error) {
	if len(b) != 32 {
		return store.DerivedKeys{}, fmt.Errorf("%w: data key", errBadCase)
	}
	return store.Derive(b)
}

func arr16(b []byte) ([16]byte, error) {
	if len(b) != 16 {
		return [16]byte{}, fmt.Errorf("%w: profile id", errBadCase)
	}
	return [16]byte(b), nil
}

//nolint:gocyclo // one arm per kind of the corpus
func answer(kind string, i in, backends Backends) (Obj, error) {
	switch kind {
	case "derive":
		dk, err := i.bytes("dk")
		if err != nil {
			return nil, err
		}
		k, err := derive(dk)
		if err != nil {
			return nil, err
		}
		v, n, x := k.Keys()
		return Obj{"k_value": h(v[:]), "k_name": h(n[:]), "k_index": h(x[:])}, nil
	case "name", "tag":
		ns, err := i.str("ns")
		if err != nil {
			return nil, err
		}
		var keys *store.DerivedKeys
		if i.has("dk") {
			dk, err := i.bytes("dk")
			if err != nil {
				return nil, err
			}
			k, err := derive(dk)
			if err != nil {
				return nil, err
			}
			keys = &k
		}
		if kind == "name" {
			id, err := i.bytes("id")
			if err != nil {
				return nil, err
			}
			var n store.Name
			if keys != nil {
				n, err = keys.Name(ns, id)
			} else {
				n, err = store.PlainName(ns, id)
			}
			if err != nil {
				return nil, err
			}
			return Obj{"name": h(n[:])}, nil
		}
		field, err := i.str("field")
		if err != nil {
			return nil, err
		}
		value, err := i.bytes("value")
		if err != nil {
			return nil, err
		}
		var t store.Tag
		if keys != nil {
			t, err = keys.Tag(ns, field, value)
		} else {
			t, err = store.PlainTag(ns, field, value)
		}
		if err != nil {
			return nil, err
		}
		return Obj{"tag": h(t.Tag[:])}, nil
	case "seal":
		return seal(i)
	case "open":
		return open(i)
	case "plain":
		ns, _ := i.str("ns")
		id, err := i.bytes("id")
		if err != nil {
			return nil, err
		}
		n, err := store.PlainName(ns, id)
		if err != nil {
			return nil, err
		}
		na, err := i.time("not_after")
		if err != nil {
			return nil, err
		}
		payload, err := i.bytes("payload")
		if err != nil {
			return nil, err
		}
		rec, err := store.PlainRecord(na, payload)
		if err != nil {
			return nil, err
		}
		return Obj{"name": h(n[:]), "record": h(rec)}, nil
	case "plain_open":
		now, err := i.num("now")
		if err != nil {
			return nil, err
		}
		rec, err := i.bytes("record")
		if err != nil {
			return nil, err
		}
		o, err := store.OpenPlain(time.Unix(int64(now), 0), rec)
		if err != nil {
			return nil, err
		}
		return Obj{"not_after": wire(o.NotAfter), "payload": h(o.Payload)}, nil
	case "keyring_write":
		return keyringWrite(i)
	case "keyring":
		return keyringRead(i)
	case "kek_file":
		content, err := i.bytes("content")
		if err != nil {
			return nil, err
		}
		mode := -1
		if i.has("mode") {
			m, err := i.num("mode")
			if err != nil {
				return nil, err
			}
			mode = int(m)
		}
		kek, err := store.ParseKEKFile(content, mode)
		if err != nil {
			return nil, err
		}
		return Obj{"kek": h(kek[:])}, nil
	case "record_file_write":
		exp, err := i.time("expires_at")
		if err != nil {
			return nil, err
		}
		tags, err := i.tags("tags")
		if err != nil {
			return nil, err
		}
		value, err := i.bytes("value")
		if err != nil {
			return nil, err
		}
		return Obj{"file": h(store.EncodeRecordFile(store.StoredRecord{Value: value, ExpiresAt: exp, Tags: tags}))}, nil
	case "record_file":
		file, err := i.bytes("file")
		if err != nil {
			return nil, err
		}
		r, err := store.ParseRecordFile(file)
		if err != nil {
			return nil, err
		}
		tags := []any{}
		for _, t := range r.Tags {
			tags = append(tags, Obj{"field": t.Field, "tag": h(t.Tag[:])})
		}
		return Obj{"expires_at": wire(r.ExpiresAt), "tags": tags, "value": h(r.Value)}, nil
	case "files_meta":
		file, err := i.bytes("file")
		if err != nil {
			return nil, err
		}
		maxLevel, err := i.num("max")
		if err != nil {
			return nil, err
		}
		m, err := store.ParseFilesMeta(file)
		if err != nil {
			return nil, err
		}
		if err := store.CheckLevel(int(maxLevel), int(m.Level), int(m.MinCompatible)); err != nil {
			return nil, err
		}
		return Obj{"level": m.Level, "min_compatible": m.MinCompatible}, nil
	case "db_level":
		var v [4]uint64
		for n, k := range []string{"max", "user_version", "level", "min_compatible"} {
			x, err := i.num(k)
			if err != nil {
				return nil, err
			}
			v[n] = x
		}
		if err := store.CheckDatabaseLevel(int(v[0]), int(v[1]), int(v[2]), int(v[3])); err != nil {
			return nil, err
		}
		return Obj{}, nil
	case "profile":
		return profile(i)
	case "capabilities", "scenario":
		name, err := i.str("backend")
		if err != nil {
			return nil, err
		}
		b, done, err := backends(name)
		if err != nil {
			return nil, err
		}
		if b == nil {
			return nil, ErrUnsupported
		}
		defer done()
		if kind == "capabilities" {
			c := b.Capabilities()
			return Obj{"atomic_take": c.AtomicTake, "atomic_batch": c.AtomicBatch, "indexed": c.Indexed, "multi_process": c.MultiProcess}, nil
		}
		steps, err := i.list("steps")
		if err != nil {
			return nil, err
		}
		results := []any{}
		for _, s := range steps {
			r, err := step(b, s)
			if err != nil {
				return nil, err
			}
			results = append(results, r)
		}
		return Obj{"results": results}, nil
	}
	return nil, ErrUnsupported
}

func seal(i in) (Obj, error) {
	dk, err := i.bytes("dk")
	if err != nil {
		return nil, err
	}
	keys, err := derive(dk)
	if err != nil {
		return nil, err
	}
	nameKeys := keys
	if i.has("index_dk") {
		idk, err := i.bytes("index_dk")
		if err != nil {
			return nil, err
		}
		if nameKeys, err = derive(idk); err != nil {
			return nil, err
		}
	}
	ns, _ := i.str("ns")
	id, err := i.bytes("id")
	if err != nil {
		return nil, err
	}
	name, err := nameKeys.Name(ns, id)
	if err != nil {
		return nil, err
	}
	pid, err := i.bytes("profile_id")
	if err != nil {
		return nil, err
	}
	p16, err := arr16(pid)
	if err != nil {
		return nil, err
	}
	kid, _ := i.str("kid")
	na, err := i.time("not_after")
	if err != nil {
		return nil, err
	}
	nonce, err := i.bytes("nonce")
	if err != nil || len(nonce) != 12 {
		return nil, fmt.Errorf("%w: nonce", errBadCase)
	}
	payload, err := i.bytes("payload")
	if err != nil {
		return nil, err
	}
	rec, err := store.SealRecord(keys.ValueKey(), p16, kid, ns, name, na, [12]byte(nonce), payload)
	if err != nil {
		return nil, err
	}
	return Obj{"name": h(name[:]), "record": h(rec)}, nil
}

func open(i in) (Obj, error) {
	ring := map[string]*store.DerivedKeys{}
	keys, ok := i.o["keys"].(Obj)
	if !ok {
		return nil, fmt.Errorf("%w: keys", errBadCase)
	}
	for kid, v := range keys {
		s, _ := v.(string)
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: keys", errBadCase)
		}
		k, err := derive(b)
		if err != nil {
			return nil, err
		}
		ring[kid] = &k
	}
	idk, err := i.bytes("index_dk")
	if err != nil {
		return nil, err
	}
	index, err := derive(idk)
	if err != nil {
		return nil, err
	}
	ns, _ := i.str("ns")
	id, err := i.bytes("id")
	if err != nil {
		return nil, err
	}
	name, err := index.Name(ns, id)
	if err != nil {
		return nil, err
	}
	pid, err := i.bytes("profile_id")
	if err != nil {
		return nil, err
	}
	p16, err := arr16(pid)
	if err != nil {
		return nil, err
	}
	now, err := i.num("now")
	if err != nil {
		return nil, err
	}
	rec, err := i.bytes("record")
	if err != nil {
		return nil, err
	}
	o, err := store.OpenSealed(func(kid string) *[32]byte {
		if k := ring[kid]; k != nil {
			return k.ValueKey()
		}
		return nil
	}, p16, ns, name, time.Unix(int64(now), 0), rec)
	if err != nil {
		return nil, err
	}
	return Obj{"kid": o.Kid, "not_after": wire(o.NotAfter), "payload": h(o.Payload)}, nil
}

func keyringWrite(i in) (Obj, error) {
	kek, err := i.bytes("kek")
	if err != nil || len(kek) != 32 {
		return nil, fmt.Errorf("%w: kek", errBadCase)
	}
	pid, err := i.bytes("profile_id")
	if err != nil {
		return nil, err
	}
	p16, err := arr16(pid)
	if err != nil {
		return nil, err
	}
	f := &store.KeyringFile{ProfileID: p16}
	f.CurrentKid, _ = i.str("current_kid")
	f.IndexKid, _ = i.str("index_kid")
	entries, err := i.list("entries")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		kid, _ := e.str("kid")
		created, err := e.time("created")
		if err != nil {
			return nil, err
		}
		dk, err := e.bytes("dk")
		if err != nil {
			return nil, err
		}
		nonce, err := e.bytes("nonce")
		if err != nil {
			return nil, err
		}
		w := store.NewKeyFileWrapper([32]byte(kek), bytes.NewReader(nonce))
		wrapped, err := w.Wrap(context.Background(), p16, kid, dk)
		if err != nil {
			return nil, err
		}
		f.Entries = append(f.Entries, store.WrappedKey{Kid: kid, Created: created, WrapperID: w.ID(), Wrapped: wrapped})
	}
	b := f.Encode()
	if _, err := store.ParseKeyringFile(b); err != nil {
		return nil, err
	}
	return Obj{"file": h(b)}, nil
}

func keyringRead(i in) (Obj, error) {
	file, err := i.bytes("file")
	if err != nil {
		return nil, err
	}
	kek, err := i.bytes("kek")
	if err != nil || len(kek) != 32 {
		return nil, fmt.Errorf("%w: kek", errBadCase)
	}
	f, err := store.ParseKeyringFile(file)
	if err != nil {
		return nil, err
	}
	w := store.NewKeyFileWrapper([32]byte(kek), bytes.NewReader(nil))
	ctx := context.Background()
	if _, err := store.OpenKeyring(ctx, f, w, bytes.NewReader(nil)); err != nil {
		return nil, err
	}
	keys := []any{}
	for _, e := range f.Entries {
		dk, err := w.Unwrap(ctx, f.ProfileID, e.Kid, e.Wrapped)
		if err != nil {
			return nil, err
		}
		keys = append(keys, Obj{"kid": e.Kid, "created": wire(e.Created), "wrapper": e.WrapperID, "dk": h(dk)})
	}
	return Obj{"profile_id": h(f.ProfileID[:]), "current_kid": f.CurrentKid, "index_kid": f.IndexKid, "keys": keys}, nil
}

func profile(i in) (Obj, error) {
	osName, err := i.str("os")
	if err != nil {
		return nil, err
	}
	p := store.Unix
	if osName == "windows" {
		p = store.Windows
	}
	env, _ := i.o["env"].(Obj)
	pin := store.ProfileInputs{Platform: p, LookupEnv: func(k string) (string, bool) {
		v, ok := env[k].(string)
		return v, ok
	}}
	if i.has("flag") {
		f, _ := i.str("flag")
		pin.Flag = &f
	}
	if i.has("active") {
		a, _ := i.str("active")
		pin.Active = &a
	}
	if i.has("home") {
		pin.Home, _ = i.str("home")
	}
	pr, err := store.ResolveProfile(pin)
	if err != nil {
		return nil, err
	}
	return Obj{
		"name": pr.Name, "from": pr.From, "active_file": pr.ActiveFile, "kek_file": pr.KEKFile,
		"keyring": pr.Keyring, "state_db": pr.StateDB, "cache_db": pr.CacheDB, "state_root": pr.StateRoot, "cache_root": pr.CacheRoot,
	}, nil
}

func code(err error) Obj { return Obj{"code": string(store.CodeOf(err))} }

func nameOf(s in, k string) (store.Name, error) {
	b, err := s.bytes(k)
	if err != nil || len(b) != 32 {
		return store.Name{}, store.ErrInvalidArgument
	}
	return store.Name(b), nil
}

func target(s in) (string, store.Name, error) {
	ns, _ := s.str("ns")
	if !store.ValidNamespace(ns) {
		return "", store.Name{}, store.ErrInvalidArgument
	}
	n, err := nameOf(s, "name")
	return ns, n, err
}

func record(s in) (string, store.Name, store.StoredRecord, error) {
	ns, n, err := target(s)
	if err != nil {
		return "", n, store.StoredRecord{}, err
	}
	tags, err := s.tags("tags")
	if err != nil {
		return "", n, store.StoredRecord{}, err
	}
	value, err := s.bytes("value")
	if err != nil {
		return "", n, store.StoredRecord{}, err
	}
	exp, err := s.time("expires_at")
	return ns, n, store.StoredRecord{Value: value, ExpiresAt: exp, Tags: tags}, err
}

//nolint:gocyclo // one arm per operation of the scenarios
func step(b store.Backend, s in) (Obj, error) {
	ctx := context.Background()
	op, err := s.str("op")
	if err != nil {
		return nil, err
	}
	nowN, _ := s.num("now")
	now := time.Unix(int64(nowN), 0)
	switch op {
	case "put":
		ns, n, r, err := record(s)
		if errors.Is(err, errBadCase) {
			return nil, err
		}
		if err == nil {
			err = b.Put(ctx, ns, n, r)
		}
		return code(err), nil
	case "get", "take":
		ns, n, err := target(s)
		var r store.StoredRecord
		if err == nil {
			if op == "get" {
				r, err = b.Get(ctx, ns, n, now)
			} else {
				r, err = b.Take(ctx, ns, n, now)
			}
		}
		if err != nil {
			return code(err), nil
		}
		return Obj{"code": "ok", "value": h(r.Value), "expires_at": wire(r.ExpiresAt)}, nil
	case "delete":
		ns, n, err := target(s)
		if err == nil {
			err = b.Delete(ctx, ns, n)
		}
		return code(err), nil
	case "batch":
		if !b.Capabilities().AtomicBatch {
			return code(store.ErrCapabilityMissing), nil
		}
		list, err := s.list("ops")
		if err != nil {
			return nil, err
		}
		var ops []store.BatchOp
		for _, o := range list {
			kind, _ := o.str("op")
			var bop store.BatchOp
			switch kind {
			case "put":
				ns, n, r, err := record(o)
				if err != nil {
					return code(err), nil
				}
				bop = store.BatchOp{NS: ns, Name: n, Record: &r}
			case "delete":
				ns, n, err := target(o)
				if err != nil {
					return code(err), nil
				}
				bop = store.BatchOp{NS: ns, Name: n}
			default:
				return code(store.ErrInvalidArgument), nil
			}
			ops = append(ops, bop)
		}
		return code(b.Batch(ctx, ops)), nil
	case "query":
		ns, _ := s.str("ns")
		q := &store.Query{NS: ns, Now: now}
		lim, _ := s.num("limit")
		q.Limit = int(lim)
		if q.Filters, err = s.tags("filters"); err != nil {
			return code(err), nil
		}
		if s.has("from") {
			q.From, _ = s.time("from")
		}
		if s.has("to") {
			q.To, _ = s.time("to")
		}
		if s.has("cursor") {
			c, err := nameOf(s, "cursor")
			if err != nil {
				return code(err), nil
			}
			q.Cursor = &c
		}
		page, err := b.Query(ctx, q)
		if err != nil {
			return code(err), nil
		}
		names := []any{}
		for _, e := range page.Records {
			names = append(names, h(e.Name[:]))
		}
		out := Obj{"code": "ok", "names": names}
		if page.Cursor != nil {
			out["cursor"] = h(page.Cursor[:])
		}
		return out, nil
	case "cleanup":
		lim, err := s.num("limit")
		if err != nil {
			return nil, err
		}
		n, err := b.Cleanup(ctx, now, int(lim))
		if err != nil {
			return code(err), nil
		}
		return Obj{"code": "ok", "removed": n}, nil
	case "fill":
		ns, _ := s.str("ns")
		seed, err := s.bytes("seed")
		if err != nil {
			return nil, err
		}
		count, err := s.num("count")
		if err != nil {
			return nil, err
		}
		exp, err := s.time("expires_at")
		if err != nil {
			return nil, err
		}
		ops := make([]store.BatchOp, 0, count)
		for n := range uint32(count) {
			idx := binary.BigEndian.AppendUint32(nil, n)
			r := store.StoredRecord{Value: idx, ExpiresAt: exp}
			ops = append(ops, store.BatchOp{NS: ns, Name: sha256.Sum256(append(bytes.Clone(seed), idx...)), Record: &r})
		}
		if b.Capabilities().AtomicBatch {
			err = b.Batch(ctx, ops)
		} else {
			for _, op := range ops {
				if err = b.Put(ctx, op.NS, op.Name, *op.Record); err != nil {
					break
				}
			}
		}
		return code(err), nil
	case "scan":
		ns, _ := s.str("ns")
		lim, err := s.num("limit")
		if err != nil {
			return nil, err
		}
		d := sha256.New()
		count := 0
		var cursor *store.Name
		for {
			page, err := b.Query(ctx, &store.Query{NS: ns, Limit: int(lim), Cursor: cursor, Now: now})
			if err != nil {
				return code(err), nil
			}
			for _, e := range page.Records {
				d.Write(e.Name[:])
			}
			count += len(page.Records)
			if page.Cursor == nil {
				break
			}
			cursor = page.Cursor
		}
		if only, _ := s.o["count_only"].(bool); only {
			return Obj{"code": "ok", "count": count}, nil
		}
		return Obj{"code": "ok", "count": count, "digest": h(d.Sum(nil))}, nil
	}
	return nil, fmt.Errorf("%w: op %s", errBadCase, op)
}
