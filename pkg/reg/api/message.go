package api

import (
	"fmt"

	"github.com/gematik/zero-lab/pkg/reg"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type VerifiedMessage struct {
	Jwk              jwk.Key
	Nonce            string
	ContentType      string
	ProtectedHeaders jws.Headers
	Payload          []byte
	Attestation      *reg.AttestationEntity
}

func ParseSignedMessage(
	messageData []byte,
	redeemNonce func(nonce string) error,
) (*VerifiedMessage, error) {
	// Parse the message to access the keys
	unsafeMessage, err := jws.Parse(messageData)
	if err != nil {
		return nil, fmt.Errorf("unable to parse message: %w", err)
	}
	// extract the signature and protected headers
	if unsafeMessage.Signatures() == nil || len(unsafeMessage.Signatures()) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	signature := unsafeMessage.Signatures()[0]
	if signature.ProtectedHeaders() == nil {
		return nil, fmt.Errorf("no protected headers found")
	}

	protectedHeaders := signature.ProtectedHeaders()

	// make sure nonce is present and redeem it
	nonceX, ok := protectedHeaders.Get("nonce")
	if !ok {
		return nil, fmt.Errorf("nonce is not present")
	}
	nonce := nonceX.(string)
	if nonce == "" {
		return nil, fmt.Errorf("nonce is empty")
	}
	err = redeemNonce(nonce)
	if err != nil {
		return nil, fmt.Errorf("unable to redeem nonce: %w", err)
	}

	// extract the key
	publicKeyJWK := protectedHeaders.JWK()

	// verify the signature
	message, err := jws.Verify(messageData, jws.WithKey(jwa.ES256, publicKeyJWK))
	if err != nil {
		return nil, fmt.Errorf("unable to verify message: %w", err)
	}

	// may be empty
	contentType := protectedHeaders.ContentType()

	// return the verified message with the key, protected headers and payload
	return &VerifiedMessage{
		Jwk:              publicKeyJWK,
		Nonce:            nonce,
		ContentType:      contentType,
		ProtectedHeaders: protectedHeaders,
		Payload:          message,
	}, nil
}

/*
func verifyAttestationHeader(header *attestationHeader, publicKey jwk.Key, nonce string) (interface{}, error) {
	switch header.Format {
	case string(reg.AttestationFormatAppleAttestation):
		return verifyAppleAttestation(header.Data, publicKey, nonce)
	default:
		return nil, fmt.Errorf("unsupported attestation format: %s", header.Format)
	}
}

func verifyAppleAttestation(dataString string, publicKey jwk.Key, nonce string) (*dcappattest.Attestation, error) {
	data, err := base64.RawURLEncoding.DecodeString(dataString)
	if err != nil {
		slog.Error("unable to decode base64", "string", dataString)
		return nil, fmt.Errorf("unable to decode base64: %w", err)
	}
	thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate thumbprint: %w", err)
	}
	clientHash := sha256.Sum256(append(thumbprint, []byte(nonce)...))
	return dcappattest.ParseAttestation([]byte(data), clientHash)
}
*/
