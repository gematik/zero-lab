package dpop

import (
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Signer func()

func SignRequest(request *http.Request, privateKey jwk.Key) error {
	token, err := NewToken(
		NewTokenId(),
		request.Method,
		request.URL.String(),
		time.Now(),
		"",
		"",
	)
	if err != nil {
		return err
	}

	signed, err := SignToken(token, privateKey)

	request.Header.Add(DPoPHeaderName, string(signed))

	return nil
}
