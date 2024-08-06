package dpop

import (
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func SignRequest(request *http.Request, privateKey jwk.Key) error {
	token := DPoP{
		JwtID:      NewTokenID(),
		HttpMethod: request.Method,
		HttpURI:    request.URL.String(),
		IssuedAt:   time.Now(),
	}

	signed, err := token.Sign(privateKey)
	if err != nil {
		return err
	}

	request.Header.Add(DPoPHeaderName, string(signed))

	return nil
}
