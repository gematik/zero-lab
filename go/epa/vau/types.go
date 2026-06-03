package vau

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/gematik/zero-lab/go/brainpool"
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

type CertData struct {
	Cert     *x509.Certificate
	CACert   *x509.Certificate
	RCAChain []*x509.Certificate
}

type certDataRaw struct {
	Cert     []byte   `cbor:"cert"`
	CA       []byte   `cbor:"ca"`
	RCAChain [][]byte `cbor:"rca_chain"`
}

func (c *CertData) UnmarshalCBOR(data []byte) error {

	raw := new(certDataRaw)
	if err := cbor.Unmarshal(data, raw); err != nil {
		return err
	}

	var err error

	if raw.Cert == nil {
		return errors.New("missing certificate")
	}

	c.Cert, err = brainpool.ParseCertificate(raw.Cert)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	if raw.CA == nil {
		return errors.New("missing CA certificate")
	}

	c.CACert, err = brainpool.ParseCertificate(raw.CA)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	if len(raw.RCAChain) == 0 {
		return errors.New("missing RCA chain")
	}

	c.RCAChain = make([]*x509.Certificate, 0, len(raw.RCAChain))
	for _, cert := range raw.RCAChain {
		rca, err := brainpool.ParseCertificate(cert)
		if err != nil {
			return fmt.Errorf("parsing RCA certificate: %w", err)
		}
		c.RCAChain = append(c.RCAChain, rca)
	}

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
