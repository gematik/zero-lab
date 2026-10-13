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
	"errors"
	"fmt"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
)

type Message1 struct {
	MessageType string
	ECDH_PK     ECDHData
	Kyber768_PK KEMData
}

type Message2 struct {
	MessageType string
	ECDH_ct     ECDHData
	Kyber768_ct []byte
	AEAD_ct     []byte
}

type Message3 struct {
	MessageType              string
	AEAD_ct                  []byte
	AEAD_ct_key_confirmation []byte
}

type Message3Inner struct {
	ECDH_ct     ECDHData
	Kyber768_ct []byte
	ERP         bool
	ESO         bool
}

type Message4 struct {
	MessageType              string
	AEAD_ct_key_confirmation []byte
}

type PublicVAUKeys struct {
	ECDH_PK     ECDHData
	Kyber768_PK KEMData
	IssuedAt    int64  `cbor:"iat"`
	ExpiresAt   int64  `cbor:"exp"`
	Commment    string `cbor:"comment"`
}

type SignedPublicVAUKeys struct {
	SignedPubKeys    *PublicVAUKeys `cbor:"-"`
	SignedPubKeysRaw []byte         `cbor:"signed_pub_keys"`
	Signature        []byte         `cbor:"signature-ES256"`
	CertHash         []byte         `cbor:"cert_hash"`
	Cdv              int            `cbor:"cdv"`
	OcspResponse     []byte         `cbor:"ocsp_response"`
}

// CertData is the VAU's certificate chain as the aggregator publishes it: the VAU
// certificate, its CA and the cross-certificates up to the root, as DER. They are
// brainpool certificates, which Go's x509 cannot parse; the verifier (the ti tool)
// reads them.
type CertData struct {
	Cert     []byte   `cbor:"cert"`
	CA       []byte   `cbor:"ca"`
	RCAChain [][]byte `cbor:"rca_chain"`
}

func (c *CertData) UnmarshalCBOR(data []byte) error {
	type raw CertData
	var decoded raw
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.Cert == nil {
		return errors.New("missing certificate")
	}
	if decoded.CA == nil {
		return errors.New("missing CA certificate")
	}
	if len(decoded.RCAChain) == 0 {
		slog.Warn("CertData missing RCA chain")
	}
	*c = CertData(decoded)
	return nil
}

// MessageError is a CBOR encoded error message
type MessageError struct {
	MessageType  string `cbor:"MessageType"`
	ErrorCode    uint64 `cbor:"ErrorCode"`
	ErrorMessage string `cbor:"ErrorMessage"`
}

func (m *MessageError) Error() string {
	return fmt.Sprintf("vau: %d %s", m.ErrorCode, m.ErrorMessage)
}
