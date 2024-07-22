// Implementation of Apple app attestation
// see https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
package dcappattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const FormatAppleAppAttest = "apple-app-attest"

const AppleAppAttestRootCA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

var roots *x509.CertPool

func init() {
	// prepare trust anchor
	roots = x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(AppleAppAttestRootCA))
}

// DAAppAttest attestation details
type Attestation struct {
	Format               string
	AttestationStatement *AttestationStatement
	AuthenticatorData    *AuthenticatorData
	RawAuthData          []byte
}

// AttestationStatement from DCAppAttest attestation object
type AttestationStatement struct {
	CredCert x509.Certificate
	CACerts  []x509.Certificate
	Receipt  []byte
}

// AuthenticatorData from DCAppAttest attestation object
type AuthenticatorData struct {
	RpidHash     []byte
	Flags        byte
	Count        uint32
	Aaguid       []byte
	CredentialId []byte
}

// ParseAttestation parses the attestation object from DCAppAttest
func ParseAttestation(attestationData []byte, clientDataHash [32]byte) (*Attestation, error) {
	var v attestationStruct
	if err := cbor.Unmarshal(attestationData, &v); err != nil {
		return nil, fmt.Errorf("unable to parse attestation: %w", err)
	}

	authData, err := parseAuthenticatorData(v.AuthData)
	if err != nil {
		return nil, fmt.Errorf("unable to parse authenticator data: %w", err)
	}

	var x5c []x509.Certificate
	for _, certRaw := range v.AttStmpt.X5c {
		c, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %w", err)
		}

		x5c = append(x5c, *c)
	}

	if len(x5c) < 2 {
		return nil, errors.New("x5c too short")
	}

	credCert := x5c[0]

	unverifiedAttestation := &Attestation{
		Format: v.Fmt,
		AttestationStatement: &AttestationStatement{
			CredCert: credCert,
			CACerts:  x5c[1:],
			Receipt:  v.AttStmpt.Receipt,
		},
		AuthenticatorData: authData,
		RawAuthData:       v.AuthData,
	}

	return verifyAttestation(unverifiedAttestation, clientDataHash)

}

// Verifies the attestation as specified by Apple here:
// https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
func verifyAttestation(a *Attestation, clientDataHash [32]byte) (*Attestation, error) {

	// 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
	// starting from the credential certificate in the first data buffer in the array (credcert).
	// Verify the validity of the certificates using Apple’s App Attest root certificate.
	caCerts := x509.NewCertPool()
	for num, cert := range a.AttestationStatement.CACerts {
		if !cert.IsCA {
			return nil, fmt.Errorf("x5c[%d] is not a CA", num)
		}
		caCerts.AddCert(&cert)
	}

	verifyOptions := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: caCerts,
		CurrentTime:   time.Now(),
	}

	if _, err := a.AttestationStatement.CredCert.Verify(verifyOptions); err != nil {
		return nil, err
	}

	// 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends
	// to your app before performing the attestation, and append that hash to the end of
	// the authenticator data (authData from the decoded object).
	nonceData := append(a.RawAuthData, clientDataHash[:]...)
	// 3. Generate a new SHA256 hash of the composite item to create nonce.
	nonce := sha256.Sum256(nonceData)
	// 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2,
	// which is a DER-encoded ASN.1 sequence. Decode the sequence and extract the single
	// octet string that it contains. Verify that the string equals nonce.
	var nonceExt []byte
	for _, ext := range a.AttestationStatement.CredCert.Extensions {
		if ext.Id.String() == "1.2.840.113635.100.8.2" {
			nonceExt = ext.Value
			break
		}
	}

	var octetValue []asn1.RawValue
	var bytesValue asn1.RawValue
	asn1.Unmarshal(nonceExt, &octetValue)
	asn1.Unmarshal(octetValue[0].Bytes, &bytesValue)
	if !bytes.Equal(bytesValue.Bytes, nonce[:]) {
		return nil, errors.New("nonce mismatch")
	}

	// 5. Create the SHA256 hash of the public key in credCert, and verify that it matches
	// the key identifier from your app.
	pubKey, ok := a.AttestationStatement.CredCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an ECDSA key")
	}
	ecdhPubKey, err := pubKey.ECDH()
	if err != nil {
		return nil, err
	}

	pubKeyHash := sha256.Sum256(ecdhPubKey.Bytes())

	// TODO: check if we need to verify the key identifier

	// 6. Compute the SHA256 hash of your app’s App ID, and verify that it’s the same as the authenticator data’s RP ID hash.
	// gematik: we will verifiy it elsewhere, because we will allow multiple app ids

	// 7. Verify that the authenticator data’s counter field equals 0.
	if a.AuthenticatorData.Count != 0 {
		return nil, errors.New("counter must be 0")
	}

	// 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if
	// operating in the development environment, or appattest followed by seven 0x00 bytes if
	// operating in the production environment.
	if !bytes.Equal(a.AuthenticatorData.Aaguid, []byte("appattestdevelop")) && !bytes.Equal(a.AuthenticatorData.Aaguid, []byte("appattest\x00\x00\x00\x00\x00\x00\x00")) {
		return nil, errors.New("aaguid mismatch")
	}

	// 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(pubKeyHash[:], a.AuthenticatorData.CredentialId) {
		return nil, errors.New("pubKeyHash mismatch")
	}

	return a, nil
}

// internal intermediate struct to store parsed data
type attestationStruct struct {
	Fmt      string                `cbor:"fmt"`
	AttStmpt attestationStmtStruct `cbor:"attStmt"`
	AuthData []byte                `cbor:"authData"`
}

// internal intermediate struct to store parsed data
type attestationStmtStruct struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// see https://www.w3.org/TR/webauthn/#sctn-authenticator-data
func parseAuthenticatorData(authData []byte) (*AuthenticatorData, error) {
	if len(authData) < 55 {
		return nil, fmt.Errorf("authData too short: %d must be at least %d", len(authData), 55)
	}
	var v AuthenticatorData
	// webauth standard
	v.RpidHash = authData[0:32]
	v.Flags = authData[32]
	v.Count = binary.BigEndian.Uint32(authData[33:37])
	// apple specific
	v.Aaguid = authData[37:53]
	credentialIdLen := binary.BigEndian.Uint16(authData[53:55])
	if len(authData) < 55+int(credentialIdLen) {
		return nil, fmt.Errorf("authData too short: %d must be at least %d", len(authData), 55+credentialIdLen)
	}
	v.CredentialId = authData[55 : 55+credentialIdLen]

	return &v, nil
}
