package nonce

import (
	"log/slog"
	"net/http"
)

type Stats struct {
	Active int
}

type NonceService interface {
	Get() (string, error)
	Redeem(nonceStr string) error
	Stats() (*Stats, error)
}

func GetNonceHandlerFunc(ns NonceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
		nonce, err := ns.Get()
		if err != nil {
			w.WriteHeader(500)
			slog.Error("Unable to get nonce", "error", err)
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
	}
}
