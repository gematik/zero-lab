// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
