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

package vau

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func unhex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// text is s as a CBOR text string.
func text(s string) []byte {
	data, err := encMode.Marshal(s)
	if err != nil {
		panic(err)
	}
	return data
}

func join(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// m4 is a Message4 under the map head given, its key confirmation encoded as given, and
// further pairs after it.
func m4(tb testing.TB, head, confirmation string, rest ...[]byte) []byte {
	tb.Helper()
	return join(append([][]byte{unhex(tb, head), text("MessageType"), text("M4"), text("AEAD_ct_key_confirmation"), unhex(tb, confirmation)}, rest...)...)
}

// vauKeysWith is lib-vau's VAU keys with further pairs appended to the map.
func vauKeysWith(tb testing.TB, pairs int, rest ...[]byte) []byte {
	tb.Helper()
	keys := readTestdata(tb, "libvau/vau_keys.cbor")
	if keys[0] != 0xa5 {
		tb.Fatalf("vau_keys.cbor no longer starts with a map of five pairs")
	}
	keys[0] += byte(pairs)
	return join(append([][]byte{keys}, rest...)...)
}

// gematik's lib-vau writes every handshake map with indefinite length, Message1 with its
// MessageType last.
func TestServerRule28_LibVauMessagesAreRead(t *testing.T) {
	for name, m := range map[string]any{
		"libvau/m1.cbor":       new(Message1),
		"libvau/m2.cbor":       new(Message2),
		"libvau/m3.cbor":       new(Message3),
		"libvau/m4.cbor":       new(Message4),
		"libvau/vau_keys.cbor": new(PublicVAUKeys),
	} {
		if err := decode(readTestdata(t, name), m); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	var keys PublicVAUKeys
	if err := decode(readTestdata(t, "libvau/vau_keys.cbor"), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.ECDHPK.Crv != "P-256" || len(keys.Kyber768PK) != 1184 || keys.ExpiresAt != 1712098574 {
		t.Errorf("keys = %s, %d, %d", keys.ECDHPK.Crv, len(keys.Kyber768PK), keys.ExpiresAt)
	}
}

// libasl (ZETA/ASL) shares Message3 and Message4 with VAU; its Message1 and Message2 name
// the ML-KEM fields differently, which VAU does not know.
func TestServerRule28_LibASLMessagesAreReadWhereTheyAreVAUs(t *testing.T) {
	for name, m := range map[string]any{
		"libasl/client_m3.cbor": new(Message3),
		"libasl/server_m3.cbor": new(Message3),
		"libasl/client_m4.cbor": new(Message4),
	} {
		if err := decode(readTestdata(t, name), m); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, m := range map[string]any{
		"libasl/client_m1.cbor": new(Message1),
		"libasl/server_m1.cbor": new(Message1),
		"libasl/client_m2.cbor": new(Message2),
		"libasl/server_m2.cbor": new(Message2),
	} {
		if err := decode(readTestdata(t, name), m); !errors.Is(err, ErrCBORUnknownField) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// libasl writes a null ocsp_response where it has none; it counts as absent, and the
// verification decides whether that is acceptable.
func TestServerRule28_ANullOCSPResponseIsAbsent(t *testing.T) {
	var signed SignedPublicVAUKeys
	if err := signed.UnmarshalCBOR(readTestdata(t, "libasl/signed_asl_keys.cbor")); err != nil {
		t.Fatal(err)
	}
	if signed.OcspResponse != nil || signed.Cdv != 42 || len(signed.CertHash) != 32 {
		t.Errorf("signed = %x, %d, %x", signed.OcspResponse, signed.Cdv, signed.CertHash)
	}
}

func TestServerRule28_NullAnywhereElseIsRefused(t *testing.T) {
	for _, value := range []string{"f6", "f7"} {
		if err := decode(m4(t, "a2", value), new(Message4)); !errors.Is(err, ErrCBORSimpleValue) {
			t.Errorf("%s: err = %v", value, err)
		}
	}
	signed := join(unhex(t, "a2"), text("signed_pub_keys"), unhex(t, "f6"), text("ocsp_response"), unhex(t, "f6"))
	if err := new(SignedPublicVAUKeys).UnmarshalCBOR(signed); !errors.Is(err, ErrCBORSimpleValue) {
		t.Errorf("signed_pub_keys: err = %v", err)
	}
	if err := new(PublicVAUKeys).UnmarshalCBOR(vauKeysWith(t, 0)); err != nil {
		t.Fatal(err)
	}
	keys := readTestdata(t, "libvau/vau_keys.cbor")
	at := bytes.Index(keys, text("comment"))
	nullComment := join(keys[:at], text("comment"), unhex(t, "f6"))
	if err := new(PublicVAUKeys).UnmarshalCBOR(nullComment); !errors.Is(err, ErrCBORSimpleValue) {
		t.Errorf("comment: err = %v", err)
	}
}

func TestServerRule28_ADuplicateKeyIsRefused(t *testing.T) {
	data := m4(t, "a3", "4101", text("AEAD_ct_key_confirmation"), unhex(t, "4101"))
	if err := decode(data, new(Message4)); !errors.Is(err, ErrCBORDuplicateKey) {
		t.Errorf("Message4: err = %v", err)
	}
	// Also in the maps whose unknown keys are ignored, and for a key they ignore.
	keys := vauKeysWith(t, 1, text("exp"), unhex(t, "00"))
	if err := new(PublicVAUKeys).UnmarshalCBOR(keys); !errors.Is(err, ErrCBORDuplicateKey) {
		t.Errorf("VAU keys, known key: err = %v", err)
	}
	keys = vauKeysWith(t, 2, text("extra"), unhex(t, "00"), text("extra"), unhex(t, "00"))
	if err := new(PublicVAUKeys).UnmarshalCBOR(keys); !errors.Is(err, ErrCBORDuplicateKey) {
		t.Errorf("VAU keys, unknown key: err = %v", err)
	}
	// lib-vau's indefinite-length maps too.
	m := readTestdata(t, "libvau/m4.cbor")
	m = join(m[:len(m)-1], text("MessageType"), text("M4"), unhex(t, "ff"))
	if err := decode(m, new(Message4)); !errors.Is(err, ErrCBORDuplicateKey) {
		t.Errorf("indefinite length: err = %v", err)
	}
}

// fxamacker's default matched "messagetype" to MessageType; a key in another case is
// another key.
func TestServerRule28_AKeyInAnotherCaseIsRefused(t *testing.T) {
	data := join(unhex(t, "a2"), text("messagetype"), text("M4"), text("AEAD_ct_key_confirmation"), unhex(t, "4101"))
	if err := decode(data, new(Message4)); !errors.Is(err, ErrCBORUnknownField) {
		t.Errorf("err = %v", err)
	}
	// In the VAU keys, a key in another case is an unknown attribute: ignored, and the key
	// it imitates stays unset.
	keys := readTestdata(t, "libvau/vau_keys.cbor")
	keys = bytes.Replace(keys, text("exp"), text("EXP"), 1)
	var decoded PublicVAUKeys
	if err := decoded.UnmarshalCBOR(keys); err != nil || decoded.ExpiresAt != 0 {
		t.Errorf("VAU keys: exp %d, err = %v", decoded.ExpiresAt, err)
	}
}

func TestServerRule28_AnUnknownKeyInAFixedMessageIsRefused(t *testing.T) {
	for name, data := range map[string][]byte{
		"text key":    m4(t, "a3", "4101", text("extra"), unhex(t, "00")),
		"integer key": m4(t, "a3", "4101", unhex(t, "01 00")),
	} {
		if err := decode(data, new(Message4)); !errors.Is(err, ErrCBORUnknownField) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	signed := join(unhex(t, "a2"), text("cdv"), unhex(t, "01"), text("extra"), unhex(t, "00"))
	if err := new(SignedPublicVAUKeys).UnmarshalCBOR(signed); !errors.Is(err, ErrCBORUnknownField) {
		t.Errorf("signed keys: err = %v", err)
	}
	certData := join(unhex(t, "a3"), text("cert"), unhex(t, "4101"), text("ca"), unhex(t, "4101"), text("extra"), unhex(t, "00"))
	if err := decode(certData, new(CertData)); !errors.Is(err, ErrCBORUnknownField) {
		t.Errorf("CertData: err = %v", err)
	}
}

// A_24425-01: a client ignores attributes of the VAU keys it does not know.
func TestA_24425_UnknownAttributesOfTheVAUKeysAreIgnored(t *testing.T) {
	keys := vauKeysWith(t, 1, text("future"), unhex(t, "a1 61 61 82 01 41 00"))
	var decoded PublicVAUKeys
	if err := decoded.UnmarshalCBOR(keys); err != nil {
		t.Fatal(err)
	}
	if decoded.ECDHPK.Crv != "P-256" || len(decoded.Kyber768PK) != 1184 {
		t.Errorf("decoded = %+v", decoded.ECDHPK)
	}
	// Ignoring them stops at the top: the key map inside is ECDH's and fixed.
	inner := readTestdata(t, "libvau/vau_keys.cbor")
	inner = bytes.Replace(inner, unhex(t, "a3 63 637276"), join(unhex(t, "a4"), text("kid"), text("1"), unhex(t, "63 637276")), 1)
	if err := new(PublicVAUKeys).UnmarshalCBOR(inner); !errors.Is(err, ErrCBORUnknownField) {
		t.Errorf("ECDH_PK: err = %v", err)
	}
}

// A_24425-01: an unknown attribute is ignored whatever it holds, within the bounds of what
// the client skips.
func TestA_24425_AnUnknownAttributeIsIgnoredWhateverItHolds(t *testing.T) {
	many := func(head string, item []byte, n int) []byte {
		return join(unhex(t, head), bytes.Repeat(item, n))
	}
	pairs := unhex(t, "b8 28")
	for i := range 40 {
		pairs = join(pairs, text(fmt.Sprintf("k%d", i)), unhex(t, "00"))
	}
	for name, value := range map[string][]byte{
		"null":                unhex(t, "f6"),
		"undefined":           unhex(t, "f7"),
		"tag":                 unhex(t, "c1 00"),
		"long array":          many("98 14", unhex(t, "00"), 20),
		"many pairs":          pairs,
		"null inside":         unhex(t, "a1 61 61 f6"),
		"nested a few levels": join(bytes.Repeat(unhex(t, "81"), maxNestedLevels), unhex(t, "00")),
	} {
		var decoded PublicVAUKeys
		if err := decoded.UnmarshalCBOR(vauKeysWith(t, 1, text("future"), value)); err != nil || len(decoded.Kyber768PK) != 1184 {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	data := join(unhex(t, "a4"), text("MessageType"), text("Error"), text("ErrorCode"), unhex(t, "03"), text("ErrorMessage"), text("x"), text("Trace"), unhex(t, "f6"))
	if err := new(MessageError).UnmarshalCBOR(data); err != nil {
		t.Errorf("error message: err = %v", err)
	}
}

// A_24635: an Aktensystem may add pairs of its own to an error.
func TestA_24635_PairsAddedToAnErrorAreIgnored(t *testing.T) {
	data := join(unhex(t, "a4"), text("MessageType"), text("Error"), text("ErrorCode"), unhex(t, "03"), text("ErrorMessage"), text("x"), text("TraceID"), text("abc"))
	var decoded MessageError
	if err := decoded.UnmarshalCBOR(data); err != nil || decoded.ErrorCode != 3 {
		t.Fatalf("err = %v, code %d", err, decoded.ErrorCode)
	}
}

func TestServerRule28_ATagIsRefused(t *testing.T) {
	for _, value := range []string{"c2 41 01", "d8 18 41 01"} {
		if err := decode(m4(t, "a2", value), new(Message4)); !errors.Is(err, ErrCBORTag) {
			t.Errorf("%s: err = %v", value, err)
		}
	}
}

func TestServerRule28_BytesAfterTheMessageAreRefused(t *testing.T) {
	if err := decode(m4(t, "a2", "4101", unhex(t, "00")), new(Message4)); !errors.Is(err, ErrCBORTrailingData) {
		t.Errorf("Message4: err = %v", err)
	}
	// The stream decoder CertData was read with stopped after the first item.
	certData := join(unhex(t, "a2"), text("cert"), unhex(t, "4101"), text("ca"), unhex(t, "4101"), unhex(t, "a0"))
	if err := decode(certData, new(CertData)); !errors.Is(err, ErrCBORTrailingData) {
		t.Errorf("CertData: err = %v", err)
	}
	if err := new(PublicVAUKeys).UnmarshalCBOR(vauKeysWith(t, 0, unhex(t, "00"))); !errors.Is(err, ErrCBORTrailingData) {
		t.Errorf("VAU keys: err = %v", err)
	}
}

func TestServerRule28_InputBeyondTheDepthOrSizeBoundIsRefused(t *testing.T) {
	deep := vauKeysWith(t, 1, text("future"), bytes.Repeat(unhex(t, "81"), maxSkippedNesting), unhex(t, "00"))
	if err := new(PublicVAUKeys).UnmarshalCBOR(deep); !errors.Is(err, ErrCBORLimit) {
		t.Errorf("depth: err = %v", err)
	}
	chain := join(unhex(t, "a3"), text("cert"), unhex(t, "4101"), text("ca"), unhex(t, "4101"), text("rca_chain"),
		unhex(t, "98 11"), bytes.Repeat(unhex(t, "4101"), maxArrayElements+1))
	if err := decode(chain, new(CertData)); !errors.Is(err, ErrCBORLimit) {
		t.Errorf("array: err = %v", err)
	}
	pairs := []byte{0xb8, maxMapPairs + 1}
	for i := range maxMapPairs + 1 {
		pairs = append(pairs, text("k"+string(rune('A'+i)))...)
		pairs = append(pairs, 0)
	}
	if err := decode(pairs, new(MessageError)); !errors.Is(err, ErrCBORLimit) {
		t.Errorf("map: err = %v", err)
	}

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("VAU-CID", "/c")
		_, _ = w.Write(make([]byte, maxMessageSize+1))
	}))
	defer stub.Close()
	if _, err := OpenChannel(stub.URL, EnvNonPU, stub.Client()); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("body: err = %v", err)
	}
}

func TestServerRule28_AnotherMessageTypeIsRefused(t *testing.T) {
	data := join(unhex(t, "a3"), text("MessageType"), text("Warning"), text("ErrorCode"), unhex(t, "03"), text("ErrorMessage"), text("x"))
	if err := decode(data, new(MessageError)); !errors.Is(err, ErrCBORMessageType) {
		t.Errorf("err = %v", err)
	}
}

// Rule 14: a refusal names the reason and at most a field, never a value of the input.
func TestServerRule28_ARefusalDoesNotQuoteTheInput(t *testing.T) {
	for name, data := range map[string][]byte{
		"duplicate": join(unhex(t, "a2"), text("SECRET-KEY"), unhex(t, "00"), text("SECRET-KEY"), unhex(t, "00")),
		"unknown":   m4(t, "a3", "4101", text("SECRET-KEY"), unhex(t, "00")),
		"type":      join(unhex(t, "a2"), text("MessageType"), text("SECRET-VALUE"), text("AEAD_ct_key_confirmation"), unhex(t, "4101")),
		"text":      join(unhex(t, "a2"), text("MessageType"), unhex(t, "4a"), []byte("SECRET-VAL"), text("AEAD_ct_key_confirmation"), unhex(t, "4101")),
	} {
		var refusals []error
		refusals = append(refusals, decode(data, new(Message4)), decode(data, new(MessageError)))
		if name == "type" {
			m := new(Message4)
			if err := decode(data, m); err == nil {
				refusals = append(refusals, checkMessageType(m.MessageType, "M4"))
			}
		}
		for _, err := range refusals {
			if err == nil {
				continue
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// Rule 14: the peer's ErrorMessage does not reach logs; the error names its code, and the message stays in its field.
func TestServerRule14_AnErrorMessageIsNotQuoted(t *testing.T) {
	m := &MessageError{ErrorCode: 3, ErrorMessage: "SECRET-MESSAGE"}
	if text := m.Error(); strings.Contains(text, "SECRET") || text != "vau: error code 3" {
		t.Errorf("Error() = %q", text)
	}
}
