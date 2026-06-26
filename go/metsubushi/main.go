package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

//go:embed index.html
var indexHTML []byte

var (
	startTime = time.Now()
	reqCount  atomic.Int64
)

func main() {
	addr := ":" + envOr("PORT", "8080")

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/api/info", handleInfo)
	mux.HandleFunc("/api/headers", handleHeaders)
	mux.HandleFunc("/api/ip", handleIP)
	mux.HandleFunc("/api/uuid", handleUUID)
	mux.HandleFunc("/api/get", handleEcho)
	mux.HandleFunc("/api/anything", handleEcho)
	mux.HandleFunc("/api/status/", handleStatus)

	srv := &http.Server{
		Addr:              addr,
		Handler:           count(secure(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Printf("metsubushi smoke test listening on %s (host=%s)\n", addr, hostname())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

// count tallies served requests; secure sets a few sane response headers.
func count(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		next.ServeHTTP(w, r)
	})
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Server", "metsubushi")
		next.ServeHTTP(w, r)
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "healthy",
		"uptimeSeconds":  int64(time.Since(startTime).Seconds()),
		"requestsServed": reqCount.Load(),
	})
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"app":            "metsubushi",
		"status":         "healthy",
		"hostname":       hostname(),
		"podName":        os.Getenv("POD_NAME"),
		"podNamespace":   os.Getenv("POD_NAMESPACE"),
		"podIP":          os.Getenv("POD_IP"),
		"nodeName":       os.Getenv("NODE_NAME"),
		"serviceName":    envOr("SERVICE_NAME", "metsubushi"),
		"logoutUrl":      os.Getenv("LOGOUT_URL"),
		"localAddresses": localAddrs(),
		"goVersion":      runtime.Version(),
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"numCPU":         runtime.NumCPU(),
		"goroutines":     runtime.NumGoroutine(),
		"pid":            os.Getpid(),
		"startedAt":      startTime.UTC().Format(time.RFC3339),
		"serverTime":     time.Now().UTC().Format(time.RFC3339),
		"uptimeSeconds":  int64(time.Since(startTime).Seconds()),
		"requestsServed": reqCount.Load(),
	})
}

func handleHeaders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"headers": flatHeaders(r),
		"host":    r.Host,
		"method":  r.Method,
		"proto":   r.Proto,
		"origin":  clientIP(r),
	})
}

func handleIP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"origin": clientIP(r)})
}

func handleUUID(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"uuid": uuidV4()})
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	args := map[string]string{}
	for k, v := range r.URL.Query() {
		args[k] = strings.Join(v, ",")
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"method":  r.Method,
		"url":     scheme + "://" + r.Host + r.URL.RequestURI(),
		"args":    args,
		"headers": flatHeaders(r),
		"origin":  clientIP(r),
		"host":    hostname(),
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/api/status/")
	code, err := strconv.Atoi(raw)
	if err != nil || code < 100 || code > 599 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "status code must be between 100 and 599"})
		return
	}
	writeJSON(w, code, map[string]any{"status": code, "text": http.StatusText(code)})
}

func flatHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func localAddrs() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func uuidV4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
