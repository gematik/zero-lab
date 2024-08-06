package api

import (
	"fmt"
	"log/slog"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type verifiedMessage struct {
	MessageRaw       []byte
	Jwk              jwk.Key
	Nonce            string
	ContentType      string
	ProtectedHeaders jws.Headers
	Payload          []byte
}

func parseSignedMessage(
	messageRaw []byte,
	redeemNonce func(nonce string) error,
) (*verifiedMessage, error) {
	// Parse the message to access the keys and redeem the nonce
	slog.Info("parsing message", "message", string(messageRaw))
	unsafeMessage, err := jws.Parse(messageRaw)
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
	payload, err := jws.Verify(messageRaw, jws.WithKey(jwa.ES256, publicKeyJWK))
	if err != nil {
		return nil, fmt.Errorf("unable to verify message: %w", err)
	}

	// may be empty
	contentType := protectedHeaders.ContentType()

	slog.Info("parsed message", "payload", string(payload))

	// return the verified message with the key, protected headers and payload
	return &verifiedMessage{
		MessageRaw:       messageRaw,
		Jwk:              publicKeyJWK,
		Nonce:            nonce,
		ContentType:      contentType,
		ProtectedHeaders: protectedHeaders,
		Payload:          payload,
	}, nil
}
