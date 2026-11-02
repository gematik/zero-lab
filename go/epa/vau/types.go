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

// Message1 opens the handshake with the client's ephemeral public keys.
type Message1 struct {
	MessageType string
	ECDHPK      ECDHData `cbor:"ECDH_PK"`
	Kyber768PK  KEMData  `cbor:"Kyber768_PK"`
}

// Message2 answers Message1: the ciphertexts to the client's ephemeral keys, and in AEADCt
// the SignedPublicVAUKeys sealed under K1_s2c.
type Message2 struct {
	MessageType string
	ECDHCt      ECDHData `cbor:"ECDH_ct"`
	Kyber768Ct  []byte   `cbor:"Kyber768_ct"`
	AEADCt      []byte   `cbor:"AEAD_ct"`
}

// Message3 carries the Message3Inner sealed under K1_c2s, and the transcript hash sealed
// under the K2 client-to-server key-confirmation key.
type Message3 struct {
	MessageType           string
	AEADCt                []byte `cbor:"AEAD_ct"`
	AEADCtKeyConfirmation []byte `cbor:"AEAD_ct_key_confirmation"`
}

// Message3Inner holds the client's ciphertexts to the VAU's keys and the ERP and ESO flags
// of the specification, which this client sends as false.
type Message3Inner struct {
	ECDHCt     ECDHData `cbor:"ECDH_ct"`
	Kyber768Ct []byte   `cbor:"Kyber768_ct"`
	ERP        bool
	ESO        bool
}

// Message4 ends the handshake: the transcript hash sealed under the K2 server-to-client
// key-confirmation key.
type Message4 struct {
	MessageType           string
	AEADCtKeyConfirmation []byte `cbor:"AEAD_ct_key_confirmation"`
}

// PublicVAUKeys are the VAU's public keys for the handshake and their validity.
type PublicVAUKeys struct {
	ECDHPK     ECDHData `cbor:"ECDH_PK"`
	Kyber768PK KEMData  `cbor:"Kyber768_PK"`
	IssuedAt   int64    `cbor:"iat"`
	ExpiresAt  int64    `cbor:"exp"`
	Commment   string   `cbor:"comment"`
}

// SignedPublicVAUKeys is PublicVAUKeys as the VAU signs them: SignedPubKeysRaw holds the
// signed CBOR, Signature its ES256 signature, CertHash and Cdv name the [CertData] of the signer.
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

// UnmarshalCBOR decodes a CertData and rejects one without certificate or CA; a missing RCA
// chain is only logged.
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
