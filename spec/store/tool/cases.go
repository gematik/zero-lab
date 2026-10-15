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
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// tc is one case as written by hand: its inputs and the code the rules give. The output
// of an ok case is computed by the reference.
type tc struct {
	id, kind, description string
	rules                 []string
	input                 obj
	want                  code
}

// All key material of the corpus is derived from labels and marked TEST-ONLY; none of it
// protects anything.
func testBytes(label string, n int) []byte { return sha([]byte("zl-store TEST-ONLY " + label))[:n] }

var (
	dk1       = testBytes("data key 1", 32)
	dk2       = testBytes("data key 2", 32)
	kek       = testBytes("key-encryption key", 32)
	otherKEK  = testBytes("other key-encryption key", 32)
	profileID = testBytes("profile", 16)
	otherProf = testBytes("other profile", 16)
	kid1      = "k1-TEST-ONLY"
	kid2      = "k2-TEST-ONLY"
	t0        = uint64(1767225600) // 2026-01-01T00:00:00Z
)

func nonce(i int) []byte { return testBytes(fmt.Sprintf("nonce %d", i), 12) }

func scenarioName(i int) string { return h(testBytes(fmt.Sprintf("scenario name %d", i), 32)) }

func scenarioTag(s string) string { return h(testBytes("scenario tag "+s, 32)) }

// mustEval runs the reference on an ok case whose output another case needs.
func mustEval(kind string, input obj) obj {
	c, out, err := evaluate(kind, input)
	if err != nil || c != codeOK {
		panic(fmt.Sprintf("%s: %v %v", kind, c, err))
	}
	return out
}

func unhex(s any) []byte {
	b, err := hex.DecodeString(s.(string))
	if err != nil {
		panic(err)
	}
	return b
}

func with(base obj, kv ...any) obj {
	out := obj{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func without(base obj, key string) obj {
	out := with(base)
	delete(out, key)
	return out
}

func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	if i < 0 {
		i += len(out)
	}
	out[i] ^= 0x01
	return out
}

func allCases() []tc {
	var cs []tc
	add := func(c tc) { cs = append(cs, c) }

	// E. Key derivation
	add(tc{id: "derive-dk1", kind: "derive", rules: []string{"STORE-041"}, input: obj{"dk": h(dk1)}, want: codeOK})
	add(tc{id: "derive-dk2", kind: "derive", rules: []string{"STORE-041"}, input: obj{"dk": h(dk2)}, want: codeOK})

	// D. Names and tags
	kvnr := []byte("TEST-ONLY-KVNR-0001")
	wk := []byte("https://idp.example.test/.well-known/openid-configuration")
	add(tc{id: "name-sealed", kind: "name", rules: []string{"STORE-031"}, input: obj{"dk": h(dk1), "ns": "popp", "id": h(kvnr)}, want: codeOK})
	add(tc{id: "name-sealed-empty-id", kind: "name", rules: []string{"STORE-030", "STORE-031"}, input: obj{"dk": h(dk1), "ns": "popp", "id": ""}, want: codeOK})
	add(tc{id: "name-sealed-max-id", kind: "name", rules: []string{"STORE-030"}, input: obj{"dk": h(dk1), "ns": "popp", "id": h(bytes.Repeat([]byte{'a'}, 4096))}, want: codeOK})
	add(tc{id: "name-id-too-long", kind: "name", rules: []string{"STORE-030"}, input: obj{"dk": h(dk1), "ns": "popp", "id": h(bytes.Repeat([]byte{'a'}, 4097))}, want: codeLimitExceeded})
	add(tc{id: "name-plain", kind: "name", rules: []string{"STORE-032"}, input: obj{"ns": "well-known", "id": h(wk)}, want: codeOK})
	add(tc{id: "name-ns-uppercase", kind: "name", rules: []string{"STORE-020"}, input: obj{"dk": h(dk1), "ns": "PoPP", "id": h(kvnr)}, want: codeInvalidArgument})
	add(tc{id: "name-ns-empty", kind: "name", rules: []string{"STORE-020"}, input: obj{"ns": "", "id": ""}, want: codeInvalidArgument})
	add(tc{id: "name-ns-leading-dot", kind: "name", rules: []string{"STORE-020"}, input: obj{"ns": ".pki", "id": ""}, want: codeInvalidArgument})
	add(tc{id: "tag-sealed", kind: "tag", rules: []string{"STORE-034"}, input: obj{"dk": h(dk1), "ns": "popp", "field": "kvnr", "value": h(kvnr)}, want: codeOK})
	add(tc{id: "tag-plain", kind: "tag", rules: []string{"STORE-034"}, input: obj{"ns": "well-known", "field": "issuer", "value": h([]byte("https://idp.example.test"))}, want: codeOK})
	add(tc{id: "tag-field-syntax", kind: "tag", rules: []string{"STORE-033"}, input: obj{"dk": h(dk1), "ns": "popp", "field": "Kvnr", "value": ""}, want: codeInvalidArgument})
	add(tc{id: "tag-value-too-long", kind: "tag", rules: []string{"STORE-033"}, input: obj{"dk": h(dk1), "ns": "popp", "field": "kvnr", "value": h(bytes.Repeat([]byte{'a'}, 4097))}, want: codeLimitExceeded})

	// F. Records
	sealIn := obj{"dk": h(dk1), "kid": kid1, "profile_id": h(profileID), "ns": "popp", "id": h(kvnr),
		"not_after": t0 + 3600, "nonce": h(nonce(1)), "payload": h([]byte("TEST-ONLY PoPP token"))}
	add(tc{id: "seal-basic", kind: "seal", rules: []string{"STORE-041", "STORE-042", "STORE-052", "STORE-053"}, input: sealIn, want: codeOK})
	noExp := with(sealIn, "ns", "comfort", "id", h([]byte("TEST-ONLY-ICCSN-80276")), "not_after", 0, "nonce", h(nonce(2)), "payload", h([]byte("TEST-ONLY user id")))
	add(tc{id: "seal-no-expiry", kind: "seal", rules: []string{"STORE-002", "STORE-053"}, input: noExp, want: codeOK})
	emptyPayload := with(sealIn, "nonce", h(nonce(3)), "payload", "")
	add(tc{id: "seal-empty-payload", kind: "seal", rules: []string{"STORE-054"}, input: emptyPayload, want: codeOK})
	sealK2 := with(sealIn, "dk", h(dk2), "index_dk", h(dk1), "kid", kid2, "nonce", h(nonce(4)))
	add(tc{id: "seal-current-kid-not-index-kid", kind: "seal", rules: []string{"STORE-042", "STORE-043"}, description: "value key of kid2, name from the index kid kid1", input: sealK2, want: codeOK})
	add(tc{id: "seal-kid-space", kind: "seal", rules: []string{"STORE-051"}, input: with(sealIn, "kid", "k 1"), want: codeInvalidArgument})

	rec := unhex(mustEval("seal", sealIn)["record"])
	recNoExp := unhex(mustEval("seal", noExp)["record"])
	recEmpty := unhex(mustEval("seal", emptyPayload)["record"])
	recK2 := unhex(mustEval("seal", sealK2)["record"])
	ring := obj{kid1: h(dk1), kid2: h(dk2)}
	openIn := obj{"keys": ring, "index_dk": h(dk1), "profile_id": h(profileID), "ns": "popp", "id": h(kvnr), "now": t0, "record": h(rec)}
	add(tc{id: "open-basic", kind: "open", rules: []string{"STORE-055"}, input: openIn, want: codeOK})
	add(tc{id: "open-no-expiry", kind: "open", rules: []string{"STORE-003", "STORE-055"},
		input: with(openIn, "ns", "comfort", "id", noExp["id"], "now", t0+100*365*86400, "record", h(recNoExp)), want: codeOK})
	add(tc{id: "open-after-rotation", kind: "open", rules: []string{"STORE-042", "STORE-043"}, description: "records of the old and the new current kid both open", input: with(openIn, "record", h(recK2)), want: codeOK})
	add(tc{id: "open-empty-payload", kind: "open", rules: []string{"STORE-055"}, input: with(openIn, "record", h(recEmpty)), want: codeOK})
	add(tc{id: "open-last-live-second", kind: "open", rules: []string{"STORE-003"}, input: with(openIn, "now", t0+3599), want: codeOK})
	add(tc{id: "open-expired-at-not-after", kind: "open", rules: []string{"STORE-003", "STORE-055"}, input: with(openIn, "now", t0+3600), want: codeExpired})
	add(tc{id: "open-other-profile", kind: "open", rules: []string{"STORE-055"}, input: with(openIn, "profile_id", h(otherProf)), want: codeAuthFailed})
	add(tc{id: "open-other-id", kind: "open", rules: []string{"STORE-055"}, input: with(openIn, "id", h([]byte("TEST-ONLY-KVNR-0002"))), want: codeAuthFailed})
	add(tc{id: "open-other-namespace", kind: "open", rules: []string{"STORE-055"}, input: with(openIn, "ns", "oauth.access"), want: codeAuthFailed})
	add(tc{id: "open-flipped-tag", kind: "open", rules: []string{"STORE-055", "STORE-056"}, input: with(openIn, "record", h(flip(rec, -1))), want: codeAuthFailed})
	kl := len(kid1)
	add(tc{id: "open-flipped-ciphertext", kind: "open", rules: []string{"STORE-056"}, input: with(openIn, "record", h(flip(rec, 2+kl+8+12))), want: codeAuthFailed})
	add(tc{id: "open-flipped-nonce", kind: "open", rules: []string{"STORE-055"}, input: with(openIn, "record", h(flip(rec, 2+kl+8))), want: codeAuthFailed})
	raised := bytes.Clone(rec)
	binary.BigEndian.PutUint64(raised[2+kl:], t0+86400)
	add(tc{id: "open-raised-not-after", kind: "open", rules: []string{"STORE-053", "STORE-055"}, description: "not_after rewritten to a later time", input: with(openIn, "now", t0+7200, "record", h(raised)), want: codeAuthFailed})
	add(tc{id: "open-unknown-kid", kind: "open", rules: []string{"STORE-055"}, input: with(openIn, "keys", obj{kid2: h(dk2)}), want: codeUnknownKid})
	add(tc{id: "open-kid-swapped", kind: "open", rules: []string{"STORE-055"}, description: "kid1 replaced by a same-length kid that is in the ring", input: with(openIn,
		"record", h(bytes.Replace(rec, []byte(kid1), []byte(kid2), 1))), want: codeAuthFailed})
	add(tc{id: "open-version-2", kind: "open", rules: []string{"STORE-050"}, input: with(openIn, "record", h(append([]byte{2}, rec[1:]...))), want: codeUnsupportedVersion})
	add(tc{id: "open-plain-in-sealed", kind: "open", rules: []string{"STORE-050"}, input: with(openIn, "record", h(append([]byte{0}, rec[1:]...))), want: codeUnsupportedVersion})
	add(tc{id: "open-empty", kind: "open", rules: []string{"STORE-005"}, input: with(openIn, "record", ""), want: codeMalformed})
	add(tc{id: "open-truncated", kind: "open", rules: []string{"STORE-005", "STORE-054"}, input: with(openIn, "record", h(rec[:2+kl+8+12+15])), want: codeMalformed})
	add(tc{id: "open-kid-len-0", kind: "open", rules: []string{"STORE-051"}, input: with(openIn, "record", h(append([]byte{1, 0}, rec[2:]...))), want: codeMalformed})
	add(tc{id: "open-kid-len-65", kind: "open", rules: []string{"STORE-051"}, input: with(openIn, "record", h(append([]byte{1, 65}, bytes.Repeat([]byte{'k'}, 120)...))), want: codeMalformed})
	spaced := bytes.Clone(rec)
	spaced[3] = ' '
	add(tc{id: "open-kid-space", kind: "open", rules: []string{"STORE-051"}, input: with(openIn, "record", h(spaced)), want: codeMalformed})

	plainIn := obj{"ns": "well-known", "id": h(wk), "not_after": t0 + 86400, "payload": h([]byte(`{"issuer":"https://idp.example.test"}`))}
	add(tc{id: "plain-basic", kind: "plain", rules: []string{"STORE-032", "STORE-050"}, input: plainIn, want: codeOK})
	prec := unhex(mustEval("plain", plainIn)["record"])
	add(tc{id: "plain-open", kind: "plain_open", rules: []string{"STORE-057"}, input: obj{"now": t0, "record": h(prec)}, want: codeOK})
	add(tc{id: "plain-open-expired", kind: "plain_open", rules: []string{"STORE-057"}, input: obj{"now": t0 + 86400, "record": h(prec)}, want: codeExpired})
	add(tc{id: "plain-open-sealed", kind: "plain_open", rules: []string{"STORE-050"}, input: obj{"now": t0, "record": h(rec)}, want: codeUnsupportedVersion})
	add(tc{id: "plain-open-short", kind: "plain_open", rules: []string{"STORE-005"}, input: obj{"now": t0, "record": h(prec[:8])}, want: codeMalformed})

	// G. Keyring
	krIn := obj{"kek": h(kek), "profile_id": h(profileID), "current_kid": kid2, "index_kid": kid1, "entries": []any{
		obj{"kid": kid1, "created": t0, "dk": h(dk1), "nonce": h(nonce(10))},
		obj{"kid": kid2, "created": t0 + 86400, "dk": h(dk2), "nonce": h(nonce(11))},
	}}
	add(tc{id: "keyring-write", kind: "keyring_write", rules: []string{"STORE-060", "STORE-061", "STORE-062", "STORE-063"}, input: krIn, want: codeOK})
	kr := unhex(mustEval("keyring_write", krIn)["file"])
	krRead := obj{"kek": h(kek), "file": h(kr)}
	add(tc{id: "keyring-read", kind: "keyring", rules: []string{"STORE-060", "STORE-063", "STORE-064"}, input: krRead, want: codeOK})
	add(tc{id: "keyring-bad-magic", kind: "keyring", rules: []string{"STORE-060"}, input: with(krRead, "file", h(append([]byte("ZLKX"), kr[4:]...))), want: codeMalformed})
	add(tc{id: "keyring-version-2", kind: "keyring", rules: []string{"STORE-060"}, input: with(krRead, "file", h(cat(kr[:4], []byte{2}, kr[5:]))), want: codeUnsupportedVersion})
	add(tc{id: "keyring-trailing", kind: "keyring", rules: []string{"STORE-005"}, input: with(krRead, "file", h(append(bytes.Clone(kr), 0))), want: codeMalformed})
	add(tc{id: "keyring-truncated", kind: "keyring", rules: []string{"STORE-005"}, input: with(krRead, "file", h(kr[:len(kr)-1])), want: codeMalformed})
	add(tc{id: "keyring-wrong-kek", kind: "keyring", rules: []string{"STORE-064"}, input: with(krRead, "kek", h(otherKEK)), want: codeAuthFailed})
	moved := cat(kr[:5], otherProf, kr[21:])
	add(tc{id: "keyring-other-profile", kind: "keyring", rules: []string{"STORE-064"}, description: "profile id replaced: the wrapped keys are bound to the old one", input: with(krRead, "file", h(moved)), want: codeAuthFailed})
	mk := func(current, index string, entries ...keyringEntry) []byte {
		return buildKeyring(keyring{profileID: profileID, currentKid: []byte(current), indexKid: []byte(index), entries: entries})
	}
	e1 := keyringEntry{kid: []byte(kid1), created: t0, wrapperID: []byte("key-file"), wrapped: wrapKeyFile(kek, profileID, []byte(kid1), nonce(10), dk1)}
	add(tc{id: "keyring-current-missing", kind: "keyring", rules: []string{"STORE-062"}, input: with(krRead, "file", h(mk(kid2, kid1, e1))), want: codeMalformed})
	add(tc{id: "keyring-duplicate-kid", kind: "keyring", rules: []string{"STORE-062"}, input: with(krRead, "file", h(mk(kid1, kid1, e1, e1))), want: codeMalformed})
	add(tc{id: "keyring-no-entries", kind: "keyring", rules: []string{"STORE-062"}, input: with(krRead, "file", h(mk(kid1, kid1))), want: codeMalformed})
	tpm := e1
	tpm.wrapperID = []byte("tpm2")
	add(tc{id: "keyring-unknown-wrapper", kind: "keyring", rules: []string{"STORE-063"}, input: with(krRead, "file", h(mk(kid1, kid1, tpm))), want: codeUnsupportedVersion})
	short := e1
	short.wrapped = e1.wrapped[:59]
	add(tc{id: "keyring-wrapped-short", kind: "keyring", rules: []string{"STORE-063"}, input: with(krRead, "file", h(mk(kid1, kid1, short))), want: codeMalformed})
	huge := cat(kr[:21], []byte{0xff, 0xff, 0xff, 0xff}, kr[25:])
	add(tc{id: "keyring-length-past-end", kind: "keyring", rules: []string{"STORE-005"}, input: with(krRead, "file", h(huge)), want: codeMalformed})

	// J. Key file
	b64 := base64.StdEncoding.EncodeToString(kek)
	add(tc{id: "kek-file", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(b64 + "\n")), "mode": 0o600}, want: codeOK})
	add(tc{id: "kek-file-no-newline", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(b64)), "mode": 0o400}, want: codeOK})
	add(tc{id: "kek-file-no-posix", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(b64))}, want: codeOK})
	add(tc{id: "kek-file-two-newlines", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(b64 + "\n\n")), "mode": 0o600}, want: codeMalformed})
	add(tc{id: "kek-file-crlf", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(b64 + "\r\n")), "mode": 0o600}, want: codeMalformed})
	add(tc{id: "kek-file-31-bytes", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(base64.StdEncoding.EncodeToString(kek[:31]))), "mode": 0o600}, want: codeMalformed})
	add(tc{id: "kek-file-raw", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h(kek), "mode": 0o600}, want: codeMalformed})
	add(tc{id: "kek-file-group-readable", kind: "kek_file", rules: []string{"STORE-094"}, input: obj{"content": h([]byte(b64)), "mode": 0o640}, want: codeInsecurePermissions})

	// I. Files backend
	rfIn := obj{"expires_at": t0 + 3600, "tags": []any{
		obj{"field": "kvnr", "tag": scenarioTag("kvnr")}, obj{"field": "iccsn", "tag": scenarioTag("iccsn")},
	}, "value": h(rec)}
	add(tc{id: "record-file-write", kind: "record_file_write", rules: []string{"STORE-080"}, input: rfIn, want: codeOK})
	rf := unhex(mustEval("record_file_write", rfIn)["file"])
	add(tc{id: "record-file-read", kind: "record_file", rules: []string{"STORE-080"}, input: obj{"file": h(rf)}, want: codeOK})
	add(tc{id: "record-file-bad-magic", kind: "record_file", rules: []string{"STORE-080"}, input: obj{"file": h(append([]byte("ZLRX"), rf[4:]...))}, want: codeMalformed})
	add(tc{id: "record-file-version-2", kind: "record_file", rules: []string{"STORE-080"}, input: obj{"file": h(cat(rf[:4], []byte{2}, rf[5:]))}, want: codeUnsupportedVersion})
	add(tc{id: "record-file-17-tags", kind: "record_file", rules: []string{"STORE-033", "STORE-080"}, input: obj{"file": h(cat(rf[:13], []byte{17}, rf[14:]))}, want: codeLimitExceeded})
	add(tc{id: "record-file-truncated-tag", kind: "record_file", rules: []string{"STORE-005"}, input: obj{"file": h(rf[:14+4+4+20])}, want: codeMalformed})
	add(tc{id: "record-file-bad-field", kind: "record_file", rules: []string{"STORE-033"}, input: obj{"file": h(bytes.Replace(rf, []byte("kvnr"), []byte("KVNR"), 1))}, want: codeMalformed})

	// K. Format levels
	meta := func(level, minC uint16) []byte {
		b := []byte("ZLFM")
		b = binary.BigEndian.AppendUint16(b, level)
		return binary.BigEndian.AppendUint16(b, minC)
	}
	add(tc{id: "files-meta-level-1", kind: "files_meta", rules: []string{"STORE-086", "STORE-100"}, input: obj{"file": h(meta(1, 1)), "max": 1}, want: codeOK})
	add(tc{id: "files-meta-newer-compatible", kind: "files_meta", rules: []string{"STORE-100", "STORE-104"}, description: "a level-2 tree after an expand migration stays open to level-1 implementations", input: obj{"file": h(meta(2, 1)), "max": 1}, want: codeOK})
	add(tc{id: "files-meta-contracted", kind: "files_meta", rules: []string{"STORE-100"}, input: obj{"file": h(meta(3, 2)), "max": 1}, want: codeUnsupportedVersion})
	add(tc{id: "files-meta-min-zero", kind: "files_meta", rules: []string{"STORE-086"}, input: obj{"file": h(meta(1, 0)), "max": 1}, want: codeMalformed})
	add(tc{id: "files-meta-min-above-level", kind: "files_meta", rules: []string{"STORE-086"}, input: obj{"file": h(meta(1, 2)), "max": 2}, want: codeMalformed})
	add(tc{id: "files-meta-trailing", kind: "files_meta", rules: []string{"STORE-005"}, input: obj{"file": h(append(meta(1, 1), 0)), "max": 1}, want: codeMalformed})
	add(tc{id: "db-level-1", kind: "db_level", rules: []string{"STORE-100", "STORE-101"}, input: obj{"user_version": 1, "level": 1, "min_compatible": 1, "max": 1}, want: codeOK})
	add(tc{id: "db-level-newer-compatible", kind: "db_level", rules: []string{"STORE-100"}, input: obj{"user_version": 2, "level": 2, "min_compatible": 1, "max": 1}, want: codeOK})
	add(tc{id: "db-level-contracted", kind: "db_level", rules: []string{"STORE-100"}, input: obj{"user_version": 2, "level": 2, "min_compatible": 2, "max": 1}, want: codeUnsupportedVersion})
	add(tc{id: "db-level-disagree", kind: "db_level", rules: []string{"STORE-101"}, input: obj{"user_version": 2, "level": 1, "min_compatible": 1, "max": 2}, want: codeMalformed})

	// J. Profiles
	linux := obj{"os": "linux", "home": "/home/test", "env": obj{}}
	add(tc{id: "profile-default", kind: "profile", rules: []string{"STORE-091", "STORE-092", "STORE-093", "STORE-094"}, input: linux, want: codeOK})
	add(tc{id: "profile-flag", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "flag", "ru-smcb", "env", obj{"TI_PROFILE": "pu"}, "active", "tu\n"), want: codeOK})
	add(tc{id: "profile-env", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "env", obj{"TI_PROFILE": "pu"}, "active", "tu\n"), want: codeOK})
	add(tc{id: "profile-active-crlf", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "active", "tu\r\nignored\n"), want: codeOK})
	add(tc{id: "profile-empty-env-falls-through", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "env", obj{"TI_PROFILE": ""}, "active", "tu"), want: codeOK})
	add(tc{id: "profile-empty-active", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "active", "\n"), want: codeOK})
	add(tc{id: "profile-flag-empty", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "flag", ""), want: codeInvalidArgument})
	add(tc{id: "profile-flag-invalid", kind: "profile", rules: []string{"STORE-090", "STORE-091"}, input: with(linux, "flag", "../x"), want: codeInvalidArgument})
	add(tc{id: "profile-active-invalid-no-fallthrough", kind: "profile", rules: []string{"STORE-091"}, input: with(linux, "active", "Prod"), want: codeInvalidArgument})
	add(tc{id: "profile-name-too-long", kind: "profile", rules: []string{"STORE-090"}, input: with(linux, "flag", "a23456789012345678901234567890123"), want: codeInvalidArgument})
	add(tc{id: "profile-xdg", kind: "profile", rules: []string{"STORE-092"}, input: with(linux, "env", obj{"XDG_STATE_HOME": "/xdg/state", "XDG_CACHE_HOME": "/xdg/cache", "XDG_CONFIG_HOME": "/xdg/config"}), want: codeOK})
	add(tc{id: "profile-xdg-relative-ignored", kind: "profile", rules: []string{"STORE-092"}, input: with(linux, "env", obj{"XDG_STATE_HOME": "rel/state", "XDG_CACHE_HOME": "rel/cache"}), want: codeOK})
	add(tc{id: "profile-overrides", kind: "profile", rules: []string{"STORE-092"}, input: with(linux, "env", obj{"TI_STATE_DIR": "/srv/ti/state", "TI_CACHE_DIR": "/srv/ti/cache"}), want: codeOK})
	add(tc{id: "profile-override-relative", kind: "profile", rules: []string{"STORE-092"}, input: with(linux, "env", obj{"TI_STATE_DIR": "state"}), want: codeInvalidArgument})
	add(tc{id: "profile-override-empty", kind: "profile", rules: []string{"STORE-092"}, input: with(linux, "env", obj{"TI_CACHE_DIR": ""}), want: codeInvalidArgument})
	add(tc{id: "profile-kek-path", kind: "profile", rules: []string{"STORE-094"}, input: with(linux, "env", obj{"TI_STORE_KEK_PATH": "/run/secrets/store.kek"}), want: codeOK})
	add(tc{id: "profile-kek-path-relative", kind: "profile", rules: []string{"STORE-094"}, input: with(linux, "env", obj{"TI_STORE_KEK_PATH": "store.kek"}), want: codeInvalidArgument})
	add(tc{id: "profile-no-home", kind: "profile", rules: []string{"STORE-092"}, input: without(linux, "home"), want: codeInvalidArgument})
	add(tc{id: "profile-macos", kind: "profile", rules: []string{"STORE-092"}, input: with(linux, "os", "darwin", "home", "/Users/test"), want: codeOK})
	windows := obj{"os": "windows", "home": `C:\Users\test`, "env": obj{"LOCALAPPDATA": `C:\Users\test\AppData\Local`, "APPDATA": `C:\Users\test\AppData\Roaming`}}
	add(tc{id: "profile-windows", kind: "profile", rules: []string{"STORE-092", "STORE-093"}, input: windows, want: codeOK})
	add(tc{id: "profile-windows-no-localappdata", kind: "profile", rules: []string{"STORE-092"}, input: with(windows, "env", obj{"APPDATA": `C:\Users\test\AppData\Roaming`}), want: codeInvalidArgument})

	// B. Capabilities and operations
	for _, b := range []string{"sqlite", "files"} {
		rules := []string{"STORE-018", "STORE-078"}
		if b == "files" {
			rules = []string{"STORE-018", "STORE-084"}
		}
		add(tc{id: "capabilities-" + b, kind: "capabilities", rules: rules, input: obj{"backend": b}, want: codeOK})
		for _, s := range scenarios() {
			add(tc{id: "scenario-" + s.id + "-" + b, kind: "scenario", rules: s.rules, description: s.description,
				input: obj{"backend": b, "steps": s.steps}, want: codeOK})
		}
	}
	return cs
}

type scenario struct {
	id, description string
	rules           []string
	steps           []any
}

func put(ns string, i int, expiresAt uint64, tags ...obj) obj {
	ts := []any{}
	for _, t := range tags {
		ts = append(ts, t)
	}
	return obj{"op": "put", "ns": ns, "name": scenarioName(i), "value": h([]byte(fmt.Sprintf("value %d", i))), "expires_at": expiresAt, "tags": ts}
}

func tg(field, value string) obj { return obj{"field": field, "tag": scenarioTag(field + "=" + value)} }

func scenarios() []scenario {
	ns := "popp"
	return []scenario{
		{id: "put-get-delete", rules: []string{"STORE-010", "STORE-011", "STORE-013"}, steps: []any{
			put(ns, 1, t0+3600),
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0},
			put(ns, 1, 0),
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0},
			obj{"op": "get", "ns": "oauth.access", "name": scenarioName(1), "now": t0},
			obj{"op": "delete", "ns": ns, "name": scenarioName(1)},
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0},
			obj{"op": "delete", "ns": ns, "name": scenarioName(1)},
		}},
		{id: "expiry", rules: []string{"STORE-003", "STORE-010", "STORE-012"}, steps: []any{
			put(ns, 1, t0+10),
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0 + 9},
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0 + 10},
			obj{"op": "take", "ns": ns, "name": scenarioName(1), "now": t0 + 10},
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0 + 9},
		}},
		{id: "take-single-use", rules: []string{"STORE-012"}, steps: []any{
			put(ns, 1, t0+3600),
			obj{"op": "take", "ns": ns, "name": scenarioName(1), "now": t0},
			obj{"op": "take", "ns": ns, "name": scenarioName(1), "now": t0},
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0},
		}},
		{id: "query-tags", rules: []string{"STORE-011", "STORE-015", "STORE-016", "STORE-035"}, steps: []any{
			put(ns, 1, t0+100, tg("kvnr", "a"), tg("iccsn", "x")),
			put(ns, 2, t0+200, tg("kvnr", "a"), tg("iccsn", "y")),
			put(ns, 3, 0, tg("kvnr", "a"), tg("kvnr", "b")),
			put(ns, 4, t0+300, tg("kvnr", "b")),
			obj{"op": "query", "ns": ns, "filters": []any{tg("kvnr", "a")}, "limit": 10, "now": t0},
			obj{"op": "query", "ns": ns, "filters": []any{tg("kvnr", "a"), tg("iccsn", "y")}, "limit": 10, "now": t0},
			obj{"op": "query", "ns": ns, "filters": []any{tg("kvnr", "b")}, "limit": 10, "now": t0},
			obj{"op": "query", "ns": ns, "limit": 10, "now": t0, "from": t0 + 150, "to": t0 + 300},
			obj{"op": "query", "ns": ns, "limit": 10, "now": t0, "from": t0 + 150},
			obj{"op": "query", "ns": ns, "limit": 10, "now": t0 + 150},
			put(ns, 1, t0+100, tg("kvnr", "c")),
			obj{"op": "query", "ns": ns, "filters": []any{tg("iccsn", "x")}, "limit": 10, "now": t0},
		}},
		{id: "query-paging", rules: []string{"STORE-015", "STORE-016"}, steps: []any{
			put(ns, 1, 0), put(ns, 2, 0), put(ns, 3, 0), put(ns, 4, 0), put(ns, 5, 0),
			obj{"op": "query", "ns": ns, "limit": 2, "now": t0},
			obj{"op": "scan", "ns": ns, "limit": 2, "now": t0},
			obj{"op": "scan", "ns": ns, "limit": 5, "now": t0},
			obj{"op": "scan", "ns": ns, "limit": 1000, "now": t0},
		}},
		{id: "invalid-arguments", rules: []string{"STORE-011", "STORE-016", "STORE-020", "STORE-033"}, steps: []any{
			obj{"op": "put", "ns": ns, "name": scenarioName(1)[:62], "value": "00", "expires_at": 0, "tags": []any{}},
			obj{"op": "put", "ns": "Popp", "name": scenarioName(1), "value": "00", "expires_at": 0, "tags": []any{}},
			put(ns, 1, 0, tg("a", "1"), tg("a", "2"), tg("a", "3"), tg("a", "4"), tg("a", "5"), tg("a", "6"), tg("a", "7"), tg("a", "8"),
				tg("a", "9"), tg("a", "10"), tg("a", "11"), tg("a", "12"), tg("a", "13"), tg("a", "14"), tg("a", "15"), tg("a", "16"), tg("a", "17")),
			obj{"op": "put", "ns": ns, "name": scenarioName(1), "value": "00", "expires_at": 0, "tags": []any{obj{"field": "Kvnr", "tag": scenarioTag("x")}}},
			obj{"op": "query", "ns": ns, "limit": 0, "now": t0},
			obj{"op": "query", "ns": ns, "limit": 1001, "now": t0},
			obj{"op": "query", "ns": ns, "limit": 10, "now": t0, "cursor": "00"},
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0},
		}},
		{id: "batch", rules: []string{"STORE-014"}, description: "a batch whose last operation is invalid applies nothing; files backends refuse batch", steps: []any{
			obj{"op": "batch", "ops": []any{put(ns, 1, 0), put(ns, 2, 0)}},
			obj{"op": "get", "ns": ns, "name": scenarioName(2), "now": t0},
			obj{"op": "batch", "ops": []any{
				obj{"op": "delete", "ns": ns, "name": scenarioName(1)}, put(ns, 3, 0),
				obj{"op": "put", "ns": ns, "name": "00", "value": "00", "expires_at": 0, "tags": []any{}},
			}},
			obj{"op": "get", "ns": ns, "name": scenarioName(1), "now": t0},
			obj{"op": "get", "ns": ns, "name": scenarioName(3), "now": t0},
		}},
		{id: "cleanup", rules: []string{"STORE-017"}, steps: []any{
			put(ns, 1, t0+10), put(ns, 2, t0+20), put(ns, 3, t0+30), put("oauth.access", 4, t0+10), put(ns, 5, 0),
			obj{"op": "cleanup", "now": t0 + 25, "limit": 2},
			obj{"op": "cleanup", "now": t0 + 25, "limit": 100},
			obj{"op": "cleanup", "now": t0 + 25, "limit": 100},
			obj{"op": "get", "ns": ns, "name": scenarioName(3), "now": t0 + 25},
			obj{"op": "cleanup", "now": t0, "limit": 0},
		}},
		{id: "many-records", rules: []string{"STORE-015", "STORE-016", "STORE-017"}, description: "100,000 records paged and cleaned up", steps: []any{
			obj{"op": "fill", "ns": ns, "count": 100000, "seed": h(testBytes("fill", 16)), "expires_at": t0 + 60},
			obj{"op": "fill", "ns": "oauth.refresh", "count": 1000, "seed": h(testBytes("fill other", 16)), "expires_at": 0},
			obj{"op": "scan", "ns": ns, "limit": 1000, "now": t0},
			obj{"op": "scan", "ns": "oauth.refresh", "limit": 1000, "now": t0},
			obj{"op": "cleanup", "now": t0 + 60, "limit": 1000},
			// which expired records a limited cleanup removes is left open (STORE-017)
			obj{"op": "scan", "ns": ns, "limit": 1000, "now": t0, "count_only": true},
			obj{"op": "scan", "ns": ns, "limit": 1000, "now": t0 + 60},
		}},
	}
}
