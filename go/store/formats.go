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

package store

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

// EncodeRecordFile is a record file of the files backend (STORE-080).
func EncodeRecordFile(r StoredRecord) []byte {
	out := binary.BigEndian.AppendUint64([]byte("ZLRF\x01"), wireTime(r.ExpiresAt))
	out = append(out, byte(len(r.Tags)))
	for _, t := range r.Tags {
		out = appendLP(out, []byte(t.Field))
		out = append(out, t.Tag[:]...)
	}
	return append(out, r.Value...)
}

// ParseRecordFile parses a record file (STORE-080).
func ParseRecordFile(b []byte) (StoredRecord, error) {
	r := &reader{b: b, what: "record file"}
	if !bytes.Equal(r.take(4), []byte("ZLRF")) {
		return StoredRecord{}, r.malformed()
	}
	if v := r.u8(); r.err == nil && v != 1 {
		return StoredRecord{}, fail(CodeUnsupportedVersion, "record file")
	}
	exp := r.u64()
	n := int(r.u8())
	if r.err != nil {
		return StoredRecord{}, r.err
	}
	if exp > MaxTime {
		return StoredRecord{}, r.malformed()
	}
	if n > MaxTags {
		return StoredRecord{}, fail(CodeLimitExceeded, "tags")
	}
	rec := StoredRecord{ExpiresAt: FromWire(exp)}
	for range n {
		field := string(r.lp())
		tag := r.take(32)
		if r.err != nil {
			return StoredRecord{}, r.err
		}
		if !ValidField(field) {
			return StoredRecord{}, r.malformed()
		}
		rec.Tags = append(rec.Tags, Tag{Field: field, Tag: [32]byte(tag)})
	}
	rec.Value = bytes.Clone(r.b)
	return rec, nil
}

// RecordPath is the path of a record below <root>/v1, with / between its parts (STORE-080).
func RecordPath(ns string, name Name) string {
	h := hex.EncodeToString(name[:])
	return ns + "/" + h[:2] + "/" + h[2:4] + "/" + h + ".rec"
}

// FilesMeta is the format level of a files tree (STORE-086).
type FilesMeta struct {
	Level, MinCompatible uint16
}

// ParseFilesMeta parses <root>/meta.
func ParseFilesMeta(b []byte) (FilesMeta, error) {
	r := &reader{b: b, what: "files meta"}
	if !bytes.Equal(r.take(4), []byte("ZLFM")) {
		return FilesMeta{}, r.malformed()
	}
	m := FilesMeta{Level: r.u16(), MinCompatible: r.u16()}
	if r.err != nil || len(r.b) != 0 || m.MinCompatible < 1 || m.MinCompatible > m.Level {
		return FilesMeta{}, r.malformed()
	}
	return m, nil
}

// Encode returns the bytes of <root>/meta.
func (m FilesMeta) Encode() []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16([]byte("ZLFM"), m.Level), m.MinCompatible)
}

// MaxLevel is the highest format level this implementation reads and writes (section K).
const MaxLevel = 1

// CheckLevel reports whether an implementation supporting levels up to max may open data
// at level that needs minCompatible (STORE-100).
func CheckLevel(maxLevel, level, minCompatible int) error {
	if minCompatible < 1 || minCompatible > level {
		return fail(CodeMalformed, "format level")
	}
	if minCompatible > maxLevel {
		return fail(CodeUnsupportedVersion, "format level")
	}
	return nil
}

// CheckDatabaseLevel adds STORE-101: user_version and meta must agree.
func CheckDatabaseLevel(maxLevel, userVersion, level, minCompatible int) error {
	if userVersion != level {
		return fail(CodeMalformed, "format level")
	}
	return CheckLevel(maxLevel, level, minCompatible)
}
