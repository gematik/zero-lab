package pep

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type OAuth2Guard struct {
	jwksFunc func() (jwk.Set, error)
	logger   slog.Logger
}

func NewOAuth2Guard(jwksFunc func() (jwk.Set, error), logger slog.Logger) (*OAuth2Guard, error) {
	return &OAuth2Guard{
		jwksFunc: jwksFunc,
		logger:   logger,
	}, nil
}

func (g *OAuth2Guard) VerifyJWTToken(token string) error {
	jwks, err := g.jwksFunc()
	if err != nil {
		return err
	}
	t, err := jwt.ParseString(token, jwt.WithKeySet(jwks))
	if err != nil {
		return err
	}
	g.logger.Debug("verified token", "claims", t)
	return nil
}

var ErrNoAuthorizationHeader = oauth2.Error{
	Code:        "no_authorization_header",
	Description: "No Authorization header in request",
}

func (g *OAuth2Guard) GuardRequest(r *http.Request, w http.ResponseWriter) error {
	autzhs := r.Header.Values("Authorization")
	if len(autzhs) == 0 {
		return ErrNoAuthorizationHeader
	}

	// we support bearer and dpop
	// we ignore other authz headers
	for _, autzh := range autzhs {
		if len(autzh) < 7 {
			continue
		}
		switch strings.ToLower(autzh[:6]) {
		case "bearer":
			return g.VerifyJWTToken(autzh[7:])
		case "dpop":
			return g.VerifyJWTToken(autzh[5:])
		}
	}

	return ErrNoAuthorizationHeader
}
