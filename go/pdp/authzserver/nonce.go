package authzserver

import (
	"fmt"
	"net/http"
)

// NonceEndpoint returns a fresh replay nonce as a text/plain body (GET only).
func (s *Server) NonceEndpoint(w http.ResponseWriter, r *http.Request) error {
	nonce, err := s.nonceService.Get()
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to get nonce: %v", err))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(nonce))
	return nil
}
