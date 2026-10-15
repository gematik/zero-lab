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

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// obj is a case's input or output as it appears in the manifest and on the adapter
// protocol: byte strings in lowercase hex, integers below 2^53.
type obj = map[string]any

// args reads typed fields from an input object and remembers the first error, so that a
// malformed case is reported once instead of at every field.
type args struct {
	o   obj
	err error
}

func (a *args) fail(field, why string) {
	if a.err == nil {
		a.err = fmt.Errorf("input %q: %s", field, why)
	}
}

func (a *args) has(field string) bool { _, ok := a.o[field]; return ok }

func (a *args) str(field string) string {
	s, ok := a.o[field].(string)
	if !ok {
		a.fail(field, "not a string")
	}
	return s
}

func (a *args) bytes(field string) []byte {
	b, err := hex.DecodeString(a.str(field))
	if err != nil {
		a.fail(field, "not hex")
	}
	return b
}

func (a *args) num(field string) uint64 {
	switch v := a.o[field].(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 0 {
			a.fail(field, "not a non-negative integer")
		}
		return uint64(n)
	case float64:
		return uint64(v)
	case int:
		return uint64(v)
	case uint64:
		return v
	}
	a.fail(field, "not a number")
	return 0
}

func (a *args) optNum(field string) *uint64 {
	if !a.has(field) {
		return nil
	}
	v := a.num(field)
	return &v
}

func (a *args) bool(field string) bool {
	b, ok := a.o[field].(bool)
	if !ok {
		a.fail(field, "not a boolean")
	}
	return b
}

func (a *args) list(field string) []obj {
	if !a.has(field) {
		return nil
	}
	raw, ok := a.o[field].([]any)
	if !ok {
		a.fail(field, "not a list")
		return nil
	}
	out := make([]obj, 0, len(raw))
	for _, r := range raw {
		o, ok := r.(obj)
		if !ok {
			a.fail(field, "not a list of objects")
			return nil
		}
		out = append(out, o)
	}
	return out
}

func (a *args) object(field string) obj {
	o, ok := a.o[field].(obj)
	if !ok {
		a.fail(field, "not an object")
	}
	return o
}

func (a *args) tags(field string) []fileTag {
	var out []fileTag
	for _, t := range a.list(field) {
		ta := &args{o: t}
		out = append(out, fileTag{field: ta.str("field"), tag: ta.bytes("tag")})
		if ta.err != nil && a.err == nil {
			a.err = ta.err
		}
	}
	return out
}

func h(b []byte) string { return hex.EncodeToString(b) }

func tagsOut(tags []fileTag) []any {
	out := []any{}
	for _, t := range tags {
		out = append(out, obj{"field": t.field, "tag": h(t.tag)})
	}
	return out
}

// errBadCase marks a case whose input does not fit its kind: a corpus error, not a verdict.
var errBadCase = errors.New("bad case")

// evaluate is the reference's answer to one case. It returns the result code and, for
// ok, the output. An error that is not a code means the case itself is broken.
func evaluate(kind string, input obj) (code, obj, error) {
	a := &args{o: input}
	out, err := evaluateKind(kind, a)
	if a.err != nil {
		return "", nil, fmt.Errorf("%w: %v", errBadCase, a.err)
	}
	if err != nil {
		var c code
		if errors.As(err, &c) {
			return c, nil, nil
		}
		return "", nil, err
	}
	return codeOK, out, nil
}

func evaluateKind(kind string, a *args) (obj, error) {
	switch kind {
	case "derive":
		d := derive(a.bytes("dk"))
		return obj{"k_value": h(d.value), "k_name": h(d.name), "k_index": h(d.index)}, nil

	case "name":
		var k []byte
		if a.has("dk") {
			k = derive(a.bytes("dk")).name
		}
		name, err := recordName(k, a.str("ns"), a.bytes("id"))
		if err != nil {
			return nil, err
		}
		return obj{"name": h(name)}, nil

	case "tag":
		var k []byte
		if a.has("dk") {
			k = derive(a.bytes("dk")).index
		}
		tag, err := recordTag(k, a.str("ns"), a.str("field"), a.bytes("value"))
		if err != nil {
			return nil, err
		}
		return obj{"tag": h(tag)}, nil

	case "seal":
		d := derive(a.bytes("dk"))
		kName := d.name
		if a.has("index_dk") {
			kName = derive(a.bytes("index_dk")).name
		}
		ns := a.str("ns")
		name, err := recordName(kName, ns, a.bytes("id"))
		if err != nil {
			return nil, err
		}
		rec, err := seal(d.value, a.bytes("profile_id"), []byte(a.str("kid")), ns, name,
			a.num("not_after"), a.bytes("nonce"), a.bytes("payload"))
		if err != nil {
			return nil, err
		}
		return obj{"name": h(name), "record": h(rec)}, nil

	case "open":
		keys := map[string][]byte{}
		for kid, dk := range a.object("keys") {
			s, _ := dk.(string)
			b, err := hex.DecodeString(s)
			if err != nil {
				a.fail("keys", "not hex")
			}
			keys[kid] = derive(b).value
		}
		ns := a.str("ns")
		name, err := recordName(derive(a.bytes("index_dk")).name, ns, a.bytes("id"))
		if err != nil {
			return nil, err
		}
		o, err := openSealed(keys, a.bytes("profile_id"), ns, name, a.num("now"), a.bytes("record"))
		if err != nil {
			return nil, err
		}
		return obj{"kid": string(o.kid), "not_after": o.notAfter, "payload": h(o.payload)}, nil

	case "plain":
		ns := a.str("ns")
		name, err := recordName(nil, ns, a.bytes("id"))
		if err != nil {
			return nil, err
		}
		rec, err := plainRecord(a.num("not_after"), a.bytes("payload"))
		if err != nil {
			return nil, err
		}
		return obj{"name": h(name), "record": h(rec)}, nil

	case "plain_open":
		o, err := openPlain(a.num("now"), a.bytes("record"))
		if err != nil {
			return nil, err
		}
		return obj{"not_after": o.notAfter, "payload": h(o.payload)}, nil

	case "keyring_write":
		kek, profileID := a.bytes("kek"), a.bytes("profile_id")
		k := keyring{profileID: profileID, currentKid: []byte(a.str("current_kid")), indexKid: []byte(a.str("index_kid"))}
		for _, e := range a.list("entries") {
			ea := &args{o: e}
			kid := []byte(ea.str("kid"))
			k.entries = append(k.entries, keyringEntry{
				kid: kid, created: ea.num("created"), wrapperID: []byte("key-file"),
				wrapped: wrapKeyFile(kek, profileID, kid, ea.bytes("nonce"), ea.bytes("dk")),
			})
			if ea.err != nil {
				a.fail("entries", ea.err.Error())
			}
		}
		file := buildKeyring(k)
		if _, err := parseKeyring(file); err != nil {
			return nil, err
		}
		return obj{"file": h(file)}, nil

	case "keyring":
		k, err := parseKeyring(a.bytes("file"))
		if err != nil {
			return nil, err
		}
		kek := a.bytes("kek")
		keys := []any{}
		for _, e := range k.entries {
			dk, err := unwrap(kek, k.profileID, e)
			if err != nil {
				return nil, err
			}
			keys = append(keys, obj{"kid": string(e.kid), "created": e.created, "wrapper": string(e.wrapperID), "dk": h(dk)})
		}
		return obj{"profile_id": h(k.profileID), "current_kid": string(k.currentKid), "index_kid": string(k.indexKid), "keys": keys}, nil

	case "kek_file":
		mode := -1
		if a.has("mode") {
			mode = int(a.num("mode"))
		}
		kek, err := parseKEKFile(a.bytes("content"), mode)
		if err != nil {
			return nil, err
		}
		return obj{"kek": h(kek)}, nil

	case "record_file_write":
		return obj{"file": h(buildRecordFile(a.num("expires_at"), a.tags("tags"), a.bytes("value")))}, nil

	case "record_file":
		exp, tags, value, err := parseRecordFile(a.bytes("file"))
		if err != nil {
			return nil, err
		}
		return obj{"expires_at": exp, "tags": tagsOut(tags), "value": h(value)}, nil

	case "files_meta":
		level, minCompatible, err := parseFilesMeta(a.bytes("file"))
		if err != nil {
			return nil, err
		}
		if err := openLevel(int(a.num("max")), level, minCompatible); err != nil {
			return nil, err
		}
		return obj{"level": level, "min_compatible": minCompatible}, nil

	case "db_level":
		level, minCompatible := int(a.num("level")), int(a.num("min_compatible"))
		if int(a.num("user_version")) != level || minCompatible < 1 || minCompatible > level {
			return nil, codeMalformed
		}
		if err := openLevel(int(a.num("max")), level, minCompatible); err != nil {
			return nil, err
		}
		return obj{}, nil

	case "profile":
		return resolveProfile(a)

	case "capabilities":
		c, ok := backendCapabilities[a.str("backend")]
		if !ok {
			a.fail("backend", "unknown")
		}
		return obj{"atomic_take": c.AtomicTake, "atomic_batch": c.AtomicBatch, "indexed": c.Indexed, "multi_process": c.MultiProcess}, nil

	case "scenario":
		return runScenario(a)
	}
	return nil, fmt.Errorf("%w: unknown kind %q", errBadCase, kind)
}

var windowsAbs = regexp.MustCompile(`^([A-Za-z]:\\|\\\\)`)

// resolveProfile is section J on given inputs: the option, the environment, the content of
// the active file if it exists, and the home directory.
func resolveProfile(a *args) (obj, error) {
	osName := a.str("os")
	windows := osName == "windows"
	env := map[string]string{}
	if a.has("env") {
		for k, v := range a.object("env") {
			s, _ := v.(string)
			env[k] = s
		}
	}
	home := ""
	if a.has("home") {
		home = a.str("home")
	}
	sep := "/"
	abs := func(p string) bool { return strings.HasPrefix(p, "/") }
	if windows {
		sep = `\`
		abs = windowsAbs.MatchString
	}
	join := func(parts ...string) string { return strings.Join(parts, sep) }

	xdg := func(name, fallback string) (string, error) {
		if v := env[name]; v != "" && abs(v) {
			return v, nil
		}
		if home == "" || !abs(home) {
			return "", codeInvalidArgument
		}
		return join(home, fallback), nil
	}
	win := func(name string) (string, error) {
		if v := env[name]; v != "" && abs(v) {
			return v, nil
		}
		return "", codeInvalidArgument
	}
	override := func(name string) (string, bool, error) {
		v, ok := env[name]
		if !ok {
			return "", false, nil
		}
		if v == "" || !abs(v) {
			return "", true, codeInvalidArgument
		}
		return v, true, nil
	}

	// STORE-091
	config := func() (string, error) {
		if windows {
			return win("APPDATA")
		}
		return xdg("XDG_CONFIG_HOME", join(".config"))
	}
	name := ""
	from := ""
	switch {
	case a.has("flag"):
		name, from = a.str("flag"), "flag"
		if name == "" {
			return nil, codeInvalidArgument
		}
	case env["TI_PROFILE"] != "":
		name, from = env["TI_PROFILE"], "env"
	}
	configDir, configErr := config()
	activeFile := ""
	if configErr == nil {
		activeFile = join(configDir, "telematik", "profiles", "active")
	}
	if name == "" && a.has("active") {
		line, _, _ := strings.Cut(a.str("active"), "\n")
		line = strings.TrimSuffix(line, "\r")
		if line != "" {
			name, from = line, "active"
		}
	}
	if name == "" {
		name, from = "default", "default"
	}
	if !profileSyntax.MatchString(name) {
		return nil, codeInvalidArgument
	}

	// STORE-092
	state, ok, err := override("TI_STATE_DIR")
	if err != nil {
		return nil, err
	}
	if !ok {
		if windows {
			base, err := win("LOCALAPPDATA")
			if err != nil {
				return nil, err
			}
			state = join(base, "state", "telematik")
		} else {
			base, err := xdg("XDG_STATE_HOME", join(".local", "state"))
			if err != nil {
				return nil, err
			}
			state = join(base, "telematik")
		}
	}
	cache, ok, err := override("TI_CACHE_DIR")
	if err != nil {
		return nil, err
	}
	if !ok {
		if windows {
			base, err := win("LOCALAPPDATA")
			if err != nil {
				return nil, err
			}
			cache = join(base, "telematik")
		} else {
			base, err := xdg("XDG_CACHE_HOME", ".cache")
			if err != nil {
				return nil, err
			}
			cache = join(base, "telematik")
		}
	}

	// STORE-094
	kek, ok, err := override("TI_STORE_KEK_PATH")
	if err != nil {
		return nil, err
	}
	if !ok {
		if configErr != nil {
			return nil, configErr
		}
		kek = join(configDir, "telematik", "profiles", name, "store.kek")
	}

	// STORE-093
	stateDir := join(state, "profiles", name)
	cacheDir := join(cache, "profiles", name)
	return obj{
		"name":        name,
		"from":        from,
		"active_file": activeFile,
		"kek_file":    kek,
		"keyring":     join(stateDir, "keyring.bin"),
		"state_db":    join(stateDir, "state.db"),
		"cache_db":    join(cacheDir, "cache.db"),
		"state_root":  join(stateDir, "state"),
		"cache_root":  join(cacheDir, "cache"),
	}, nil
}

// runScenario plays a scenario's steps on the reference backend and reports one result
// per step, so that adapters are compared step by step.
func runScenario(a *args) (obj, error) {
	caps, ok := backendCapabilities[a.str("backend")]
	if !ok {
		a.fail("backend", "unknown")
		return nil, nil
	}
	m := newMemBackend(caps)
	results := []any{}
	for _, s := range a.list("steps") {
		results = append(results, runStep(m, &args{o: s}, a))
	}
	return obj{"results": results}, nil
}

func codeOf(err error) string {
	if err == nil {
		return string(codeOK)
	}
	var c code
	if errors.As(err, &c) {
		return string(c)
	}
	return err.Error()
}

func runStep(m *memBackend, s, parent *args) obj {
	defer func() {
		if s.err != nil && parent.err == nil {
			parent.err = s.err
		}
	}()
	switch op := s.str("op"); op {
	case "put":
		err := m.put(s.str("ns"), s.bytes("name"), s.bytes("value"), s.num("expires_at"), s.tags("tags"))
		return obj{"code": codeOf(err)}
	case "get", "take":
		var r memRecord
		var err error
		if op == "get" {
			r, err = m.get(s.str("ns"), s.bytes("name"), s.num("now"))
		} else {
			r, err = m.take(s.str("ns"), s.bytes("name"), s.num("now"))
		}
		if err != nil {
			return obj{"code": codeOf(err)}
		}
		return obj{"code": "ok", "value": h(r.value), "expires_at": r.expiresAt}
	case "delete":
		return obj{"code": codeOf(m.delete(s.str("ns"), s.bytes("name")))}
	case "batch":
		var ops []batchOp
		for _, o := range s.list("ops") {
			oa := &args{o: o}
			b := batchOp{op: oa.str("op"), ns: oa.str("ns"), name: oa.bytes("name")}
			if b.op == "put" {
				b.value, b.expiresAt, b.tags = oa.bytes("value"), oa.num("expires_at"), oa.tags("tags")
			}
			if oa.err != nil && s.err == nil {
				s.err = oa.err
			}
			ops = append(ops, b)
		}
		return obj{"code": codeOf(m.batch(ops))}
	case "query":
		q := queryArgs{ns: s.str("ns"), filters: s.tags("filters"), from: s.optNum("from"), to: s.optNum("to"),
			limit: int(s.num("limit")), now: s.num("now")}
		if s.has("cursor") {
			q.cursor = s.bytes("cursor")
		}
		names, cursor, err := m.query(q)
		if err != nil {
			return obj{"code": codeOf(err)}
		}
		out := obj{"code": "ok", "names": hexList(names)}
		if cursor != nil {
			out["cursor"] = h(cursor)
		}
		return out
	case "cleanup":
		n, err := m.cleanup(s.num("now"), int(s.num("limit")))
		if err != nil {
			return obj{"code": codeOf(err)}
		}
		return obj{"code": "ok", "removed": n}
	case "fill":
		seed, ns, exp := s.bytes("seed"), s.str("ns"), s.num("expires_at")
		for i := range int(s.num("count")) {
			if err := m.put(ns, fillName(seed, i), fillValue(i), exp, nil); err != nil {
				return obj{"code": codeOf(err)}
			}
		}
		return obj{"code": "ok"}
	case "scan":
		n, digest, err := m.scan(s.str("ns"), int(s.num("limit")), s.num("now"))
		if err != nil {
			return obj{"code": codeOf(err)}
		}
		if s.has("count_only") && s.bool("count_only") {
			return obj{"code": "ok", "count": n}
		}
		return obj{"code": "ok", "count": n, "digest": h(digest)}
	default:
		s.fail("op", "unknown operation "+op)
		return obj{}
	}
}

func hexList(bs [][]byte) []any {
	out := []any{}
	for _, b := range bs {
		out = append(out, h(b))
	}
	return out
}
