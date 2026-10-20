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
	"encoding/binary"
	"errors"
)

// STORE-001: lp(x) is a 32-bit big-endian length, then x.
func appendLP(out, x []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(x)))
	return append(out, x...)
}

func asError(err error, target **Error) bool { return errors.As(err, target) }

// reader reads one structure; every failure is malformed with the structure's name, and
// no length field makes it read or allocate past its input (STORE-005).
type reader struct {
	b    []byte
	what string
	err  error
}

func (r *reader) malformed() error { return fail(CodeMalformed, r.what) }

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = r.malformed()
		return nil
	}
	out := r.b[:n:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *reader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (r *reader) lp() []byte {
	b := r.take(4)
	if b == nil {
		return nil
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(r.b)) {
		r.err = r.malformed()
		return nil
	}
	return r.take(int(n))
}
