package dcappattest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// internal intermediate struct to store parsed data
type assertionStruct struct {
	AuthenticatorData []byte `cbor:"authenticatorData"`
	Signature         []byte `cbor:"signature"`
}

type Assertion struct {
	AuthenticatorData    *SimplifiedAuthenticatorData
	RawAuthenticatorData []byte
	Signature            []byte
}

func ParseAssertion(assertionData []byte, clientDataHash [32]byte, pubKey interface{}, sigCounter uint32) (*Assertion, error) {
	var cborVal assertionStruct
	if err := cbor.Unmarshal(assertionData, &cborVal); err != nil {
		return nil, err
	}

	authData, err := parseSimplifiedAuthenticatorData(cborVal.AuthenticatorData)
	if err != nil {
		return nil, err
	}

	v := &Assertion{
		AuthenticatorData:    authData,
		RawAuthenticatorData: cborVal.AuthenticatorData,
		Signature:            cborVal.Signature,
	}

	// Verify as described at https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
	// 1. Compute clientDataHash as the SHA256 hash of clientData.
	// -> We get it as a parameter
	// 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
	nonceData := append(v.RawAuthenticatorData, clientDataHash[:]...)
	nonce := sha256.Sum256(nonceData)
	// 3. Use the public key that you store from the attestation object to verify that the assertion’s
	// signature is valid for nonce.
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ECDSA key")
	}
	// calculate hash over nonce (even though it is already a hash)
	nonceHash := sha256.Sum256(nonce[:])
	valid := ecdsa.VerifyASN1(ecdsaPubKey, nonceHash[:], v.Signature)
	if !valid {
		return nil, fmt.Errorf("signature invalid")
	}
	// 4. Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
	// -> we verify it elsewhere

	// 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
	if sigCounter >= v.AuthenticatorData.Count {
		return nil, fmt.Errorf("signature counter invalid")
	}

	// 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
	// -> we verify it elsewhere

	return v, nil

}

type SimplifiedAuthenticatorData struct {
	RpidHash []byte
	Flags    byte
	Count    uint32
}

func parseSimplifiedAuthenticatorData(authData []byte) (*SimplifiedAuthenticatorData, error) {
	var v SimplifiedAuthenticatorData

	if len(authData) < 37 {
		return nil, fmt.Errorf("authData too short: %d must be at least %d", len(authData), 37)
	}
	// webauthn standard
	v.RpidHash = authData[0:32]
	v.Flags = authData[32]
	v.Count = binary.BigEndian.Uint32(authData[33:37])

	return &v, nil
}
