package authzserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// handlerFunc is an HTTP handler that returns an error. Errors are rendered as an
// OAuth 2.0 JSON error (RFC 6749 §5.2) by handle().
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

// handle adapts a handlerFunc to http.HandlerFunc, rendering a returned error as an
// OAuth JSON error. A *Error keeps its status/code; any other error becomes 500
// server_error. This replaces the former echo ErrorHandlerMiddleware.
func (s *Server) handle(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		slog.Error("request error", "error", err, "path", r.URL.Path, "remote_addr", realIP(r))
		if authzErr, ok := err.(*Error); ok {
			_ = writeJSON(w, authzErr.HttpStatus, authzErr)
			return
		}
		_ = writeJSON(w, http.StatusInternalServerError, &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: err.Error(),
		})
	}
}

// writeJSON writes v as an application/json response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// realIP returns a best-effort client IP for logging (X-Forwarded-For / X-Real-IP / RemoteAddr).
func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if before, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(before)
		}
		return strings.TrimSpace(xff)
	}
	if xrip := r.Header.Get("X-Real-Ip"); xrip != "" {
		return xrip
	}
	return r.RemoteAddr
}

// formBinder binds request form fields to string targets, collecting the first error.
// It replaces echo.FormFieldBinder. Form values come from the query (GET) and the
// urlencoded body (POST), matching the previous behavior.
type formBinder struct {
	r   *http.Request
	err error
}

func newFormBinder(r *http.Request) *formBinder {
	b := &formBinder{r: r}
	if err := r.ParseForm(); err != nil {
		b.err = fmt.Errorf("parse form: %w", err)
	}
	return b
}

// MustString requires the field to be present, else records an error.
func (b *formBinder) MustString(name string, dst *string) *formBinder {
	if b.err != nil {
		return b
	}
	if !b.r.Form.Has(name) {
		b.err = fmt.Errorf("required field %q is missing", name)
		return b
	}
	*dst = b.r.Form.Get(name)
	return b
}

// String binds the field if present; absence is not an error.
func (b *formBinder) String(name string, dst *string) *formBinder {
	if b.err != nil {
		return b
	}
	if b.r.Form.Has(name) {
		*dst = b.r.Form.Get(name)
	}
	return b
}

func (b *formBinder) BindError() error { return b.err }

// --- middleware (replaces echo's middleware.Logger / middleware.Recover and provides
// uniform OAuth JSON errors for framework-level responses such as 404 / 405) ---

// Recover recovers from a handler panic and returns a 500 OAuth JSON error.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "recover", rec, "path", r.URL.Path)
				_ = writeJSON(w, http.StatusInternalServerError, &Error{
					HttpStatus:  http.StatusInternalServerError,
					Code:        "server_error",
					Description: "internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Logger logs one line per request (method, path, status, duration).
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration", time.Since(start).String(), "remote_addr", realIP(r))
	})
}

// OAuthErrors normalizes any error response that is not already JSON (e.g. ServeMux's
// plain-text 404 / 405) into the OAuth JSON error shape, so ALL errors are OAuth-formatted.
func OAuthErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&errorNormalizingWriter{ResponseWriter: w}, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// errorNormalizingWriter rewrites a non-JSON >=400 response into an OAuth JSON error and
// swallows the original plain body. JSON responses (set by writeJSON) and 2xx pass through.
type errorNormalizingWriter struct {
	http.ResponseWriter
	wroteHeader bool
	override    bool
}

func (w *errorNormalizingWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	ct := w.Header().Get("Content-Type")
	if code >= 400 && !strings.HasPrefix(ct, "application/json") {
		w.override = true
		w.Header().Set("Content-Type", "application/json")
		w.ResponseWriter.WriteHeader(code)
		_ = json.NewEncoder(w.ResponseWriter).Encode(oauthErrorForStatus(code))
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *errorNormalizingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.override {
		// swallow the framework's plain-text body; we already wrote the JSON error.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func oauthErrorForStatus(code int) *Error {
	e := &Error{HttpStatus: code, Description: http.StatusText(code)}
	switch code {
	case http.StatusNotFound:
		e.Code = "not_found"
	case http.StatusMethodNotAllowed:
		e.Code = "method_not_allowed"
	default:
		e.Code = "server_error"
	}
	return e
}
