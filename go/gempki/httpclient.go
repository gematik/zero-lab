package gempki

import (
	"net/http"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// defaultHTTPClient is the bounded fallback used when a caller passes a nil *http.Client. Production
// callers should pass their own configured client; this ensures even the fallback carries a timeout
// rather than the unbounded http.DefaultClient.
var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
