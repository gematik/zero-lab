package dpop

import (
	"fmt"
	"net/http"
)

func SignRequest(request *http.Request, privateKey *PrivateKey) error {

	token, err := NewBuilder().
		HttpRequest(request).
		Build()
	if err != nil {
		return fmt.Errorf("build DPoP token: %w", err)
	}

	signed, err := token.Sign(privateKey)
	if err != nil {
		return err
	}

	request.Header.Add(DPoPHeaderName, string(signed))

	return nil
}
