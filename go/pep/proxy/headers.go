package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

const (
	headerUser     = "X-Auth-Request-User"
	headerEmail    = "X-Auth-Request-Email"
	headerGroups   = "X-Auth-Request-Groups"
	headerIdentity = "X-Auth-Request-Identity"
)

// setIdentityHeaders writes the oauth2-proxy identity headers from the session identity claims, after
// clearing any client-supplied copies (anti-spoofing). X-Auth-Request-Identity carries the full claims as
// base64url(JSON) for upstreams that want everything.
func setIdentityHeaders(h http.Header, identity map[string]any) {
	h.Del(headerUser)
	h.Del(headerEmail)
	h.Del(headerGroups)
	h.Del(headerIdentity)
	if len(identity) == 0 {
		return
	}
	if v := claimString(identity, "preferred_username", "sub"); v != "" {
		h.Set(headerUser, v)
	}
	if v := claimString(identity, "email"); v != "" {
		h.Set(headerEmail, v)
	}
	if v := claimCSV(identity, "groups"); v != "" {
		h.Set(headerGroups, v)
	}
	if enc := encodeIdentity(identity); enc != "" {
		h.Set(headerIdentity, enc)
	}
}

func claimString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func claimCSV(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

// encodeIdentity renders the identity claims as base64url(JSON). Returns "" when empty.
func encodeIdentity(identity map[string]any) string {
	if len(identity) == 0 {
		return ""
	}
	b, err := json.Marshal(identity)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
