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
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func sampleECDH() ECDHData {
	return ECDHData{Crv: "P-256", X: bytes.Repeat([]byte{1}, 32), Y: bytes.Repeat([]byte{2}, 32)}
}

// sampleMessages are one message of each type with every field set, as the client and the
// test server send them.
func sampleMessages(tb testing.TB) []any {
	tb.Helper()
	keys := PublicVAUKeys{ECDHPK: sampleECDH(), Kyber768PK: make([]byte, 1184), IssuedAt: 1700000000, ExpiresAt: -1, Commment: "VAU-Instanz äöü"}
	keysRaw, err := encMode.Marshal(keys)
	if err != nil {
		tb.Fatal(err)
	}
	return []any{
		&Message1{MessageType: "M1", ECDHPK: sampleECDH(), Kyber768PK: make([]byte, 1184)},
		&Message2{MessageType: "M2", ECDHCt: sampleECDH(), Kyber768Ct: make([]byte, 1088), AEADCt: make([]byte, 300)},
		&Message3{MessageType: "M3", AEADCt: make([]byte, 1200), AEADCtKeyConfirmation: make([]byte, 60)},
		&Message3Inner{ECDHCt: sampleECDH(), Kyber768Ct: make([]byte, 1088), ERP: true},
		&Message4{MessageType: "M4", AEADCtKeyConfirmation: make([]byte, 60)},
		&keys,
		&SignedPublicVAUKeys{SignedPubKeysRaw: keysRaw, Signature: make([]byte, 64), CertHash: make([]byte, 32), Cdv: 1, OcspResponse: make([]byte, 1500)},
		&CertData{Cert: make([]byte, 900), CA: make([]byte, 1000), RCAChain: [][]byte{make([]byte, 800), make([]byte, 800)}},
		&MessageError{MessageType: "Error", ErrorCode: 3, ErrorMessage: "decryption failed"},
	}
}

func seeds(f *testing.F, files ...string) {
	for _, m := range sampleMessages(f) {
		data, err := encMode.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, name := range files {
		f.Add(readTestdata(f, name))
	}
}

// strictDecoding holds, for one input: a refusal gives one of the package's reasons; what is
// accepted, fxamacker's lenient default accepts too, and its encoding is a fixed point of
// decoding and encoding again.
func strictDecoding[T any](t *testing.T, data []byte, decodeInto func([]byte, *T) error) {
	ours := new(T)
	if err := decodeInto(data, ours); err != nil {
		if !slices.ContainsFunc(refusals, func(target error) bool { return errors.Is(err, target) }) {
			t.Fatalf("refused for no reason of the package: %v", err)
		}
		return
	}
	if err := cbor.Unmarshal(data, new(T)); err != nil {
		t.Fatalf("accepted what fxamacker's default refuses: %v", err)
	}
	encoded, err := encMode.Marshal(ours)
	if err != nil {
		t.Fatalf("encoding a decoded message: %v", err)
	}
	again := new(T)
	if err := decodeInto(encoded, again); err != nil {
		t.Fatalf("own encoding refused: %v", err)
	}
	if reencoded, _ := encMode.Marshal(again); !bytes.Equal(encoded, reencoded) {
		t.Fatalf("encoding is not a fixed point:\n%x\n%x", encoded, reencoded)
	}
}

func decodeInto[T any](data []byte, v *T) error { return decode(data, v) }

func FuzzMessage1(f *testing.F) {
	seeds(f, "libvau/m1.cbor", "libasl/client_m1.cbor", "libasl/client_m1_b.cbor", "libasl/server_m1.cbor", "libasl/server_m1_2.cbor")
	f.Fuzz(func(t *testing.T, data []byte) { strictDecoding(t, data, decodeInto[Message1]) })
}

func FuzzMessage2(f *testing.F) {
	seeds(f, "libvau/m2.cbor", "libasl/client_m2.cbor", "libasl/server_m2.cbor")
	f.Fuzz(func(t *testing.T, data []byte) { strictDecoding(t, data, decodeInto[Message2]) })
}

func FuzzMessage3(f *testing.F) {
	seeds(f, "libvau/m3.cbor", "libasl/client_m3.cbor", "libasl/server_m3.cbor")
	f.Fuzz(func(t *testing.T, data []byte) { strictDecoding(t, data, decodeInto[Message3]) })
}

func FuzzMessage3Inner(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, data []byte) { strictDecoding(t, data, decodeInto[Message3Inner]) })
}

func FuzzMessage4(f *testing.F) {
	seeds(f, "libvau/m4.cbor", "libasl/client_m4.cbor")
	f.Fuzz(func(t *testing.T, data []byte) { strictDecoding(t, data, decodeInto[Message4]) })
}

func FuzzPublicVAUKeys(f *testing.F) {
	seeds(f, "libvau/vau_keys.cbor")
	f.Fuzz(func(t *testing.T, data []byte) {
		strictDecoding(t, data, func(data []byte, v *PublicVAUKeys) error { return v.UnmarshalCBOR(data) })
	})
}

func FuzzSignedPublicVAUKeys(f *testing.F) {
	seeds(f, "libasl/signed_asl_keys.cbor")
	f.Fuzz(func(t *testing.T, data []byte) {
		strictDecoding(t, data, func(data []byte, v *SignedPublicVAUKeys) error { return v.UnmarshalCBOR(data) })
	})
}

func FuzzCertData(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, data []byte) { strictDecoding(t, data, decodeInto[CertData]) })
}

func FuzzMessageError(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		strictDecoding(t, data, func(data []byte, v *MessageError) error { return v.UnmarshalCBOR(data) })
	})
}
