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

// Package ber re-encodes BER (X.690 §8) as DER (X.690 §10) for the subset of
// differences that PKCS#12 producers use: indefinite lengths, non-minimal
// lengths and constructed (segmented) strings.
//
// Java keystores, Windows and card vendors write PKCS#12 files this way, while
// golang.org/x/crypto/cryptobyte only reads DER. Content is not reordered: SET
// OF elements keep their order, which is what PKCS#12 readers need, since the
// MAC covers octets and no signature covers a SET.
package ber

import (
	"errors"
	"fmt"
)

// ErrMalformed reports input that is not a valid BER encoding.
var ErrMalformed = errors.New("ber: malformed encoding")

// maxDepth bounds recursion. A PKCS#12 layer nests about ten levels; the
// limit keeps hostile input from exhausting the stack.
const maxDepth = 64

const (
	classUniversal   = 0x00
	constructedFlag  = 0x20
	tagBitString     = 3
	tagOctetString   = 4
	indefiniteLength = 0x80
)

// ToDER returns the DER encoding of the single BER element in data. Trailing
// bytes after the element are an error.
func ToDER(data []byte) ([]byte, error) {
	out, rest, err := convert(data, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(rest))
	}
	return out, nil
}

// header is a decoded identifier and length.
type header struct {
	ident      []byte // identifier octets as received
	class      byte
	tag        uint64
	compound   bool
	length     int // -1 for indefinite
	headerSize int
}

func readHeader(data []byte) (header, error) {
	var h header
	if len(data) < 2 {
		return h, fmt.Errorf("%w: truncated header", ErrMalformed)
	}
	h.class = data[0] & 0xc0
	h.compound = data[0]&constructedFlag != 0
	i := 1
	if data[0]&0x1f != 0x1f {
		h.tag = uint64(data[0] & 0x1f)
	} else {
		// High tag number form (X.690 §8.1.2.4): base-128, most significant first.
		for {
			if i >= len(data) {
				return h, fmt.Errorf("%w: truncated tag", ErrMalformed)
			}
			if h.tag > 1<<56 {
				return h, fmt.Errorf("%w: tag number too large", ErrMalformed)
			}
			b := data[i]
			i++
			h.tag = h.tag<<7 | uint64(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	h.ident = data[:i]
	// Universal tag 0 is reserved for end-of-contents (X.690 §8.1.5), which
	// readChildren consumes before reading a header.
	if h.class == classUniversal && h.tag == 0 {
		return h, fmt.Errorf("%w: unexpected end-of-contents", ErrMalformed)
	}

	if i >= len(data) {
		return h, fmt.Errorf("%w: truncated length", ErrMalformed)
	}
	first := data[i]
	i++
	switch {
	case first < 0x80:
		h.length = int(first)
	case first == indefiniteLength:
		if !h.compound {
			return h, fmt.Errorf("%w: indefinite length on a primitive element", ErrMalformed)
		}
		h.length = -1
	case first == 0xff:
		return h, fmt.Errorf("%w: reserved length octet", ErrMalformed)
	default:
		n := int(first & 0x7f)
		if n > 4 || i+n > len(data) {
			return h, fmt.Errorf("%w: unsupported or truncated length", ErrMalformed)
		}
		for _, b := range data[i : i+n] {
			h.length = h.length<<8 | int(b)
		}
		// A four-byte length overflows int on 32-bit platforms.
		if h.length < 0 {
			return h, fmt.Errorf("%w: length overflows int", ErrMalformed)
		}
		i += n
	}
	h.headerSize = i
	if h.length > len(data)-i {
		return h, fmt.Errorf("%w: length %d exceeds the %d bytes available", ErrMalformed, h.length, len(data)-i)
	}
	return h, nil
}

// convert converts the element at the start of data and returns the rest.
func convert(data []byte, depth int) (out, rest []byte, err error) {
	if depth > maxDepth {
		return nil, nil, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, maxDepth)
	}
	h, err := readHeader(data)
	if err != nil {
		return nil, nil, err
	}

	if !h.compound {
		end := h.headerSize + h.length
		return appendElement(nil, h.ident, data[h.headerSize:end]), data[end:], nil
	}

	children, rest, err := readChildren(data[h.headerSize:], h.length, depth)
	if err != nil {
		return nil, nil, err
	}

	if h.class == classUniversal && isStringType(h.tag) {
		value, err := joinSegments(h.tag, children, depth)
		if err != nil {
			return nil, nil, err
		}
		// A constructed string becomes primitive in DER (X.690 §10.2).
		ident := append([]byte{h.ident[0] &^ constructedFlag}, h.ident[1:]...)
		return appendElement(nil, ident, value), rest, nil
	}

	var content []byte
	for _, child := range children {
		der, _, err := convert(child, depth+1)
		if err != nil {
			return nil, nil, err
		}
		content = append(content, der...)
	}
	return appendElement(nil, h.ident, content), rest, nil
}

// readChildren splits the content of a constructed element into its child
// encodings (still BER) and returns the bytes after the element.
func readChildren(data []byte, length, depth int) (children [][]byte, rest []byte, err error) {
	if length >= 0 {
		content := data[:length]
		for len(content) > 0 {
			n, err := elementSize(content, depth+1)
			if err != nil {
				return nil, nil, err
			}
			children = append(children, content[:n])
			content = content[n:]
		}
		return children, data[length:], nil
	}

	// Indefinite length: children until the end-of-contents octets 00 00.
	for {
		if len(data) < 2 {
			return nil, nil, fmt.Errorf("%w: missing end-of-contents", ErrMalformed)
		}
		if data[0] == 0 && data[1] == 0 {
			return children, data[2:], nil
		}
		n, err := elementSize(data, depth+1)
		if err != nil {
			return nil, nil, err
		}
		children = append(children, data[:n])
		data = data[n:]
	}
}

// elementSize returns the number of bytes the BER element at the start of data
// occupies, including the end-of-contents octets of indefinite lengths.
func elementSize(data []byte, depth int) (int, error) {
	if depth > maxDepth {
		return 0, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, maxDepth)
	}
	h, err := readHeader(data)
	if err != nil {
		return 0, err
	}
	if h.length >= 0 {
		return h.headerSize + h.length, nil
	}
	_, rest, err := readChildren(data[h.headerSize:], -1, depth)
	if err != nil {
		return 0, err
	}
	return len(data) - len(rest), nil
}

// joinSegments concatenates the segments of a constructed string. Segments
// must carry the same universal tag and may be constructed themselves
// (X.690 §8.21.4).
func joinSegments(tag uint64, segments [][]byte, depth int) ([]byte, error) {
	var value []byte
	for i, segment := range segments {
		der, _, err := convert(segment, depth+1)
		if err != nil {
			return nil, err
		}
		h, err := readHeader(der)
		if err != nil {
			return nil, err
		}
		if h.class != classUniversal || h.tag != tag {
			return nil, fmt.Errorf("%w: segment of a constructed string has a different tag", ErrMalformed)
		}
		part := der[h.headerSize:]
		if tag == tagBitString {
			// Every segment starts with its unused-bits count; only the last
			// segment may have unused bits (X.690 §8.6.4).
			if len(part) == 0 || (i < len(segments)-1 && part[0] != 0) {
				return nil, fmt.Errorf("%w: invalid BIT STRING segment", ErrMalformed)
			}
			if i == 0 {
				value = append(value, part[0])
			} else {
				value[0] = part[0]
			}
			part = part[1:]
		}
		value = append(value, part...)
	}
	if tag == tagBitString && len(segments) == 0 {
		value = []byte{0}
	}
	return value, nil
}

// isStringType reports whether a universal tag is a string type that BER may
// encode in constructed form (X.690 §8.6, §8.7, §8.23).
func isStringType(tag uint64) bool {
	switch tag {
	case tagBitString, tagOctetString,
		12,                 // UTF8String
		18, 19, 20, 21, 22, // NumericString, PrintableString, TeletexString, VideotexString, IA5String
		25, 26, 27, 28, 30: // GraphicString, VisibleString, GeneralString, UniversalString, BMPString
		return true
	}
	return false
}

// appendElement appends an element with a minimal definite length.
func appendElement(out, ident, content []byte) []byte {
	out = append(out, ident...)
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = append(out, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		out = append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, content...)
}
