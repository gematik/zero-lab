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
	"errors"
)

// toBER re-encodes DER the way Java keystores and card vendors write PKCS#12
// files: every constructed element with indefinite length, every OCTET STRING
// longer than segment bytes as a constructed string of segment-sized parts.
//
// Only the encoding of the outer structure changes. The values of OCTET
// STRINGs (the authSafe octets the MAC covers, certificates, ciphertexts) stay
// byte for byte, so MACs and digests remain valid (CONFORMANCE.md, Encodings).
func toBER(der []byte, segment int) ([]byte, error) {
	var out []byte
	for len(der) > 0 {
		ident, compound, isOctetString, content, size, err := readTLV(der)
		if err != nil {
			return nil, err
		}
		switch {
		case compound:
			inner, err := toBER(content, segment)
			if err != nil {
				return nil, err
			}
			out = append(out, ident...)
			out = append(out, 0x80)
			out = append(out, inner...)
			out = append(out, 0, 0)
		case isOctetString && len(content) > segment:
			out = append(out, ident[0]|0x20, 0x80)
			for len(content) > 0 {
				n := min(segment, len(content))
				out = appendTLV(out, ident, content[:n])
				content = content[n:]
			}
			out = append(out, 0, 0)
		default:
			out = append(out, der[:size]...)
		}
		der = der[size:]
	}
	return out, nil
}

var errNotDER = errors.New("toBER: input is not DER")

// readTLV reads one DER element (low tag numbers and definite lengths only,
// which is all PKCS#12 uses).
func readTLV(der []byte) (ident []byte, compound, isOctetString bool, content []byte, size int, err error) {
	if len(der) < 2 || der[0]&0x1f == 0x1f {
		return nil, false, false, nil, 0, errNotDER
	}
	ident = der[:1]
	compound = der[0]&0x20 != 0
	isOctetString = der[0] == 0x04
	length, i := int(der[1]), 2
	switch {
	case length == 0x80:
		return nil, false, false, nil, 0, errNotDER
	case length > 0x80:
		n := length & 0x7f
		if n > 4 || len(der) < 2+n {
			return nil, false, false, nil, 0, errNotDER
		}
		length = 0
		for _, b := range der[2 : 2+n] {
			length = length<<8 | int(b)
		}
		i += n
	}
	if length < 0 || length > len(der)-i {
		return nil, false, false, nil, 0, errNotDER
	}
	return ident, compound, isOctetString, der[i : i+length], i + length, nil
}

func appendTLV(out, ident, content []byte) []byte {
	out = append(out, ident...)
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}
