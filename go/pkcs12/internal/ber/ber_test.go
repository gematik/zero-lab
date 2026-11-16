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

package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestToDER(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// X.690 §8.6.4.2: the BIT STRING '0A3B5F291CD'H, primitive and as a
		// constructed indefinite-length encoding of two segments.
		{"X.690 8.6.4.2 primitive", "03 07 04 0A 3B 5F 29 1C D0", "03 07 04 0A 3B 5F 29 1C D0"},
		{"X.690 8.6.4.2 constructed", "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00", "03 07 04 0A 3B 5F 29 1C D0"},

		{"DER passes through", "30 06 02 01 03 04 01 AA", "30 06 02 01 03 04 01 AA"},
		{"indefinite SEQUENCE", "30 80 02 01 03 00 00", "30 03 02 01 03"},
		{"nested indefinite", "30 80 30 80 05 00 00 00 00 00", "30 04 30 02 05 00"},
		{"segmented OCTET STRING", "24 80 04 02 01 02 04 01 03 00 00", "04 03 01 02 03"},
		{"definite segmented OCTET STRING", "24 07 04 02 01 02 04 01 03", "04 03 01 02 03"},
		{"nested segments", "24 80 24 80 04 01 01 00 00 04 01 02 00 00", "04 02 01 02"},
		{"empty constructed OCTET STRING", "24 80 00 00", "04 00"},
		{"segmented BMPString", "3E 80 1E 02 00 41 1E 02 00 42 00 00", "1E 04 00 41 00 42"},
		{"non-minimal length", "04 82 00 02 AA BB", "04 02 AA BB"},
		{"context-specific constructed keeps form", "A0 80 04 01 AA 00 00", "A0 03 04 01 AA"},
		{"high tag number", "BF 81 00 80 05 00 00 00", "BF 81 00 02 05 00"},
		{"high tag number 31", "DF 1F 00", "DF 1F 00"},
		{"high tag number 2^32-1", "9F 8F FF FF FF 7F 00", "9F 8F FF FF FF 7F 00"},
		{"empty constructed BIT STRING", "23 80 00 00", "03 01 00"},
		{"BIT STRING last segment empty", "23 80 03 02 00 0A 03 01 00 00 00", "03 02 00 0A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToDER(unhex(t, tt.in))
			if err != nil {
				t.Fatalf("ToDER: %v", err)
			}
			if want := unhex(t, tt.want); !bytes.Equal(got, want) {
				t.Errorf("ToDER = % X, want % X", got, want)
			}
		})
	}
}

func TestToDERLongContent(t *testing.T) {
	value := bytes.Repeat([]byte{0x5a}, 70000)
	der := appendElement(nil, []byte{0x04}, value)
	got, err := ToDER(toBER(der, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, der) {
		t.Error("70000-byte OCTET STRING does not round-trip")
	}
}

func TestToDERRejects(t *testing.T) {
	deep := bytes.Repeat([]byte{0x30, 0x80}, maxDepth+2)
	deep = append(deep, bytes.Repeat([]byte{0, 0}, maxDepth+2)...)

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated header", []byte{0x30}},
		{"length beyond input", unhex(t, "04 05 01 02")},
		{"missing end-of-contents", unhex(t, "30 80 05 00")},
		{"indefinite primitive", unhex(t, "04 80 01 00 00")},
		{"reserved length octet", unhex(t, "04 FF 00")},
		{"five-byte length", unhex(t, "04 85 00 00 00 00 01 AA")},
		{"trailing data", unhex(t, "05 00 00")},
		{"segment with other tag", unhex(t, "24 80 0C 01 41 00 00")},
		{"BIT STRING segment with unused bits", unhex(t, "23 80 03 02 04 0A 03 02 00 3B 00 00")},
		{"empty BIT STRING segment", unhex(t, "23 80 03 00 00 00")},
		{"truncated high tag", []byte{0x1f, 0x81}},
		{"end-of-contents as element", unhex(t, "30 04 30 02 00 00")},
		{"too deep", deep},
		{"high tag number below 31", unhex(t, "A0 80 FF 09 00 00 00")},
		{"high tag number with a leading zero group", unhex(t, "1F 80 1F 00")},
		{"high tag number above 32 bits", unhex(t, "7F 9E 82 A0 FF FF FF 00 00")},
		{"high tag number 2^32", unhex(t, "9F 90 80 80 80 00 00")},
		{"BIT STRING segment with unused bits above 7", unhex(t, "23 80 03 02 00 0A 03 02 08 00 00 00")},
		{"BIT STRING segment with unused bits and no bits", unhex(t, "23 80 03 02 00 A0 03 01 05 00 00")},
		{"universal tag 15", unhex(t, "0F 00")},
		{"primitive SEQUENCE", unhex(t, "10 00")},
		{"constructed INTEGER", unhex(t, "22 03 02 01 00")},
		{"segmented GraphicString", unhex(t, "39 80 19 01 41 00 00")},
		{"UniversalString", unhex(t, "1C 00")},
		{"universal type in the high form", unhex(t, "1F 81 00 00")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ToDER(tt.in); !errors.Is(err, ErrMalformed) {
				t.Errorf("ToDER error = %v, want ErrMalformed", err)
			}
		})
	}
}

// toBER re-encodes DER the way legacy PKCS#12 producers do: every constructed
// element with indefinite length, every OCTET STRING longer than segment bytes
// split into a constructed string of segments.
func toBER(der []byte, segment int) []byte {
	var out []byte
	for len(der) > 0 {
		h, err := readHeader(der)
		if err != nil || h.length < 0 {
			panic("toBER: input is not DER")
		}
		content := der[h.headerSize : h.headerSize+h.length]
		switch {
		case h.compound:
			out = append(out, h.ident...)
			out = append(out, indefiniteLength)
			out = append(out, toBER(content, segment)...)
			out = append(out, 0, 0)
		case h.class == classUniversal && h.tag == tagOctetString && len(content) > segment:
			out = append(out, h.ident[0]|constructedFlag, indefiniteLength)
			for len(content) > 0 {
				n := min(segment, len(content))
				out = appendElement(out, h.ident, content[:n])
				content = content[n:]
			}
			out = append(out, 0, 0)
		default:
			out = append(out, der[:h.headerSize+h.length]...)
		}
		der = der[h.headerSize+h.length:]
	}
	return out
}

func FuzzToDER(f *testing.F) {
	f.Add(unhex(f, "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00"))
	f.Add(unhex(f, "30 80 24 80 04 02 01 02 04 01 03 00 00 A0 80 05 00 00 00 00 00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		der, err := ToDER(data)
		if err != nil {
			return
		}
		again, err := ToDER(der)
		if err != nil || !bytes.Equal(again, der) {
			t.Fatalf("ToDER is not idempotent on % X", der)
		}
		back, err := ToDER(toBER(der, 3))
		if err != nil || !bytes.Equal(back, der) {
			t.Fatalf("toBER/ToDER does not round-trip % X", der)
		}
	})
}
