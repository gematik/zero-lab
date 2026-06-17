package authzserver

import (
	"fmt"
	"net/http"
)

type NonceType struct {
	Nonce string `json:"nonce"`
}

// NonceEndpoint returns a fresh replay nonce — as JSON on GET, or in the Replay-Nonce
// header on HEAD.
func (s *Server) NonceEndpoint(w http.ResponseWriter, r *http.Request) error {
	nonce, err := s.nonceService.Get()
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to get nonce: %v", err))
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Replay-Nonce", nonce)
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return writeJSON(w, http.StatusOK, NonceType{Nonce: nonce})
}
