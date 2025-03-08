package oauth2client

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2"
)

type callbackServer struct {
}

type Callback struct {
	Code        string
	HttpRequest *http.Request
	Error       error
}

var ErrTimeout = errors.New("Timeout")

func StartCallbackServer(address string, path string, timeout time.Duration) <-chan Callback {
	channel := make(chan Callback)

	// Create a custom ServeMux
	mux := http.NewServeMux()

	stopChan := make(chan *Callback)

	// Register the handler function for POST requests at /submit
	mux.HandleFunc(fmt.Sprintf("GET %s", path), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("error") != "" {
			stopChan <- &Callback{
				HttpRequest: r,
				Error: &oauth2.Error{
					Code:        r.URL.Query().Get("error"),
					Description: r.URL.Query().Get("error_description"),
				},
			}
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			stopChan <- &Callback{
				HttpRequest: r,
				Error: Error{
					Code:        "invalid_request",
					Description: "Authorization code ist missing in callback request",
				},
			}
			return
		}

		stopChan <- &Callback{
			HttpRequest: r,
			Code:        code,
		}
	})

	// Create the server using your custom mux
	server := &http.Server{
		Addr:    "127.0.0.1:8089",
		Handler: mux,
	}

	go func() {
		select {
		case <-time.After(timeout):
			channel <- Callback{Error: ErrTimeout}
			server.Close()
		case callback := <-stopChan:
			channel <- *callback
			server.Close()
		}

	}()

	slog.Info("Starting OAuth callback server", "url", fmt.Sprintf("http://%s%s", address, path))
	go func() {
		err := server.ListenAndServe()
		if err != http.ErrServerClosed {
			channel <- Callback{Error: err}
		}
	}()

	return channel
}
