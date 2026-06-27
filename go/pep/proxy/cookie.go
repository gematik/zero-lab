package proxy

import "net/http"

// newCookieTemplate builds the session-cookie template. SameSite=Lax (not Strict): the login redirect comes
// back from the IdP cross-site, and a Strict cookie would be withheld on that landing navigation — the
// session would look absent and the forward_auth gate would loop. Lax still sends the cookie on top-level
// GET navigations (CSRF on state-changing endpoints is covered by the X-Requested-With check). Secure by
// default: the __Host- prefix + Secure (the strongest binding compatible with Lax). The insecure flag drops
// both so http://127.0.0.1 dev works. The cookie value is always the opaque session id; tokens never leave
// the server.
func newCookieTemplate(name string, insecure bool) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if !insecure {
		c.Name = "__Host-" + name
		c.Secure = true
	}
	return c
}

func setCookie(w http.ResponseWriter, tmpl *http.Cookie, value string) {
	c := *tmpl
	c.Value = value
	http.SetCookie(w, &c)
}

func expireCookie(w http.ResponseWriter, tmpl *http.Cookie) {
	c := *tmpl
	c.Value = ""
	c.MaxAge = -1
	http.SetCookie(w, &c)
}
