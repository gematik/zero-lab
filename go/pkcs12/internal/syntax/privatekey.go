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

package syntax

import (
	"fmt"
	"math"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The P12-041 check reads the DER octets by hand rather than with cryptobyte:
// the rule admits high tag numbers in the parameters, which cryptobyte does not
// read, and bounds OIDs and tag numbers explicitly, so that rust/ti-pkcs12 can
// hold the same bounds (spec/pkcs12 P12-041).

const (
	// pkiMaxDepth bounds the nesting the check walks, the PrivateKeyInfo at
	// depth 0 (P12-004).
	pkiMaxDepth = 64
	// maxOIDLength bounds the content octets of the algorithm OID (P12-041).
	maxOIDLength = 39

	classUniversal = 0x00
	classContext   = 0x80

	tagInteger     = 2
	tagBitString   = 3
	tagOctetString = 4
	tagOID         = 6
	tagSequence    = 16
)

// derElement is one element read in DER form.
type derElement struct {
	class       byte
	constructed bool
	tag         uint32
	content     []byte
}

func (e derElement) is(class byte, constructed bool, tag uint32) bool {
	return e.class == class && e.constructed == constructed && e.tag == tag
}

// readDER reads the element at the start of data in DER form (X.690 §10):
// the low tag form for numbers up to 30, a minimal high form above with at
// most 32 bits, a definite length in the fewest octets.
func readDER(data []byte) (derElement, []byte, bool) {
	if len(data) < 2 {
		return derElement{}, nil, false
	}
	e := derElement{class: data[0] & 0xc0, constructed: data[0]&0x20 != 0, tag: uint32(data[0] & 0x1f)}
	i := 1
	if e.tag == 0x1f {
		var tag uint32
		for {
			if i >= len(data) || (i == 1 && data[i] == 0x80) || tag > math.MaxUint32>>7 {
				return derElement{}, nil, false
			}
			b := data[i]
			i++
			tag = tag<<7 | uint32(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
		if tag < 0x1f {
			return derElement{}, nil, false
		}
		e.tag = tag
	}
	if i >= len(data) {
		return derElement{}, nil, false
	}
	first := data[i]
	i++
	var length uint64
	switch {
	case first < 0x80:
		length = uint64(first)
	case first >= 0x81 && first <= 0x84:
		n := int(first & 0x7f)
		if n > len(data)-i || data[i] == 0 {
			return derElement{}, nil, false
		}
		for _, b := range data[i : i+n] {
			length = length<<8 | uint64(b)
		}
		if length < 0x80 {
			return derElement{}, nil, false
		}
		i += n
	default:
		return derElement{}, nil, false
	}
	if length > uint64(len(data)-i) {
		return derElement{}, nil, false
	}
	end := i + int(length)
	e.content = data[i:end]
	return e, data[end:], true
}

// universalForm reports whether a universal tag is one this specification
// reads, in the form DER gives it: SEQUENCE and SET constructed, the others
// primitive (X.690 §10.2 for strings).
func universalForm(tag uint32, constructed bool) bool {
	switch tag {
	case 16, 17:
		return constructed
	case 1, 2, 3, 4, 5, 6, 9, 10, 12, 13, 18, 19, 20, 21, 22, 23, 24, 26, 27, 30:
		return !constructed
	}
	return false
}

// checkElements reports whether content is a run of DER elements, each
// checked as at depth.
func checkElements(content []byte, depth int) bool {
	for len(content) > 0 {
		e, rest, ok := readDER(content)
		if !ok || !checkElement(e, depth) {
			return false
		}
		content = rest
	}
	return true
}

func checkElement(e derElement, depth int) bool {
	if depth > pkiMaxDepth {
		return false
	}
	if e.class == classUniversal {
		if !universalForm(e.tag, e.constructed) {
			return false
		}
		if e.tag == tagBitString && !derBitString(e.content) {
			return false
		}
	}
	return !e.constructed || checkElements(e.content, depth+1)
}

// derBitString reports whether content is the content of a DER BIT STRING:
// an initial octet of 0 to 7 unused bits, 0 without further octets, and the
// unused bits zero (X.690 §8.6.2, §11.2.1).
func derBitString(content []byte) bool {
	if len(content) == 0 || content[0] > 7 || (len(content) == 1 && content[0] != 0) {
		return false
	}
	return content[len(content)-1]&(1<<content[0]-1) == 0
}

// checkOID reports whether content is the content of an OBJECT IDENTIFIER
// within P12-041's bounds: 1 to 39 octets, every subidentifier minimal
// (X.690 §8.19.2) and below 2^32.
func checkOID(content []byte) bool {
	if len(content) == 0 || len(content) > maxOIDLength || content[len(content)-1]&0x80 != 0 {
		return false
	}
	var value uint64
	start := true
	for _, b := range content {
		if start && b == 0x80 {
			return false
		}
		value = value<<7 | uint64(b&0x7f)
		if value > math.MaxUint32 {
			return false
		}
		start = b&0x80 == 0
		if start {
			value = 0
		}
	}
	return true
}

// CheckPrivateKeyInfo checks that data is one DER PrivateKeyInfo (P12-041; RFC 5208
// §5, as OneAsymmetricKey in RFC 5958 §2) and nothing else. A wrong password
// on a file without MAC leaves valid padding in about 1 of 256 decryptions;
// the plaintext is random then, and this check is what refuses it before it
// is returned as a key.
func CheckPrivateKeyInfo(data []byte) error {
	// OneAsymmetricKey ::= SEQUENCE { version INTEGER { v1(0), v2(1) },
	//   privateKeyAlgorithm AlgorithmIdentifier, privateKey OCTET STRING,
	//   attributes [0] IMPLICIT Attributes OPTIONAL,
	//   publicKey [1] IMPLICIT BIT STRING OPTIONAL -- v2 only }
	pki, rest, ok := readDER(data)
	if !ok || len(rest) != 0 || !pki.is(classUniversal, true, tagSequence) || !checkElement(pki, 0) {
		return fmt.Errorf("%w: PrivateKeyInfo is not one DER element of the types it may hold", ErrParse)
	}
	fields := pki.content
	next := func() (derElement, bool) {
		e, rest, ok := readDER(fields)
		if ok {
			fields = rest
		}
		return e, ok
	}
	version, ok := next()
	if !ok || !version.is(classUniversal, false, tagInteger) || len(version.content) != 1 || version.content[0] > 1 {
		return fmt.Errorf("%w: PrivateKeyInfo version is not 0 or 1", ErrParse)
	}
	algorithm, ok := next()
	if !ok || !algorithm.is(classUniversal, true, tagSequence) || !checkAlgorithm(algorithm.content) {
		return fmt.Errorf("%w: cannot read the PrivateKeyInfo algorithm", ErrParse)
	}
	privateKey, ok := next()
	if !ok || !privateKey.is(classUniversal, false, tagOctetString) || len(privateKey.content) == 0 {
		return fmt.Errorf("%w: cannot read the PrivateKeyInfo private key", ErrParse)
	}
	if e, _, ok := readDER(fields); ok && e.is(classContext, true, 0) {
		next()
	}
	if e, _, ok := readDER(fields); ok && version.content[0] == 1 && e.is(classContext, false, 1) {
		if !derBitString(e.content) {
			return fmt.Errorf("%w: PrivateKeyInfo public key is not a DER BIT STRING", ErrParse)
		}
		next()
	}
	if len(fields) != 0 {
		return fmt.Errorf("%w: trailing data in PrivateKeyInfo", ErrParse)
	}
	return nil
}

// checkAlgorithm checks the content of the AlgorithmIdentifier: an OID within
// bounds and at most one parameters element, which checkElement has already
// walked.
func checkAlgorithm(content []byte) bool {
	oid, rest, ok := readDER(content)
	if !ok || !oid.is(classUniversal, false, tagOID) || !checkOID(oid.content) {
		return false
	}
	if len(rest) == 0 {
		return true
	}
	_, rest, ok = readDER(rest)
	return ok && len(rest) == 0
}

// JoinPublicKey returns the keyBag PrivateKeyInfo der, normalised from BER, with
// a constructed publicKey [1] joined into its primitive form. Generic BER to DER
// conversion leaves it constructed, since only the schema tells that this [1]
// is a BIT STRING (P12-002, as P12-005 for encryptedContent). Input that is no
// DER SEQUENCE comes back unchanged for CheckPrivateKeyInfo to refuse.
func JoinPublicKey(der []byte) ([]byte, error) {
	pki, rest, ok := readDER(der)
	if !ok || len(rest) != 0 || !pki.is(classUniversal, true, tagSequence) {
		return der, nil
	}
	var b cryptobyte.Builder
	joined := false
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		content := pki.content
		for len(content) > 0 {
			e, next, ok := readDER(content)
			if !ok {
				b.AddBytes(content)
				return
			}
			if e.is(classContext, true, 1) {
				value, err := joinBitString(e.content)
				if err != nil {
					b.SetError(err)
					return
				}
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes(value)
				})
				joined = true
			} else {
				b.AddBytes(content[:len(content)-len(next)])
			}
			content = next
		}
	})
	out, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if !joined {
		return der, nil
	}
	return out, nil
}

// joinBitString joins the BIT STRING segments of a constructed BIT STRING: only
// the last may have unused bits, and none has unused bits without bits
// (X.690 §8.6.2, §8.6.4).
func joinBitString(segments []byte) ([]byte, error) {
	value := []byte{0}
	for len(segments) > 0 {
		e, rest, ok := readDER(segments)
		if !ok || !e.is(classUniversal, false, tagBitString) || len(e.content) == 0 ||
			e.content[0] > 7 || (len(e.content) == 1 && e.content[0] != 0) ||
			(value[0] != 0) {
			return nil, fmt.Errorf("%w: invalid segment of the PrivateKeyInfo public key", ErrParse)
		}
		value[0] = e.content[0]
		value = append(value, e.content[1:]...)
		segments = rest
	}
	return value, nil
}
