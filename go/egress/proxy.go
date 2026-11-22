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

package egress

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ErrProxy is a forward proxy configuration the egress client refuses (servers.md rules 17 and 30).
var ErrProxy = errors.New("egress: forward proxy refused")

// Proxy is the forward proxy of the egress client (servers.md rule 30), an untrusted neighbour. https goes through
// it by CONNECT only, so TLS still ends at the origin, which is verified as without a proxy, and the proxy sees host
// names and nothing else; no CA of the proxy is ever accepted, so a TLS-intercepting proxy fails the handshake.
// Plain http, which the egress client sends only for data that proves itself, is forwarded through it.
type Proxy struct {
	// HTTPS is the proxy of https requests (HTTPS_PROXY), HTTP that of plain http requests (HTTP_PROXY); nil goes
	// direct.
	HTTPS, HTTP *url.URL
	// NoProxy lists the hosts reached direct, as NO_PROXY does: comma-separated host names, which match their
	// subdomains too ("example.com", ".example.com"), IP addresses and CIDR prefixes, each with an optional port,
	// and "*" for all. Loopback addresses and "localhost" are always reached direct.
	NoProxy string
	// Credentials authenticate the client at the proxy (Proxy-Authorization, Basic). They are a secret and come
	// from a file the host reads ([ParseProxyCredentials]), never from a proxy URL.
	Credentials *url.Userinfo
}

// ProxyFromEnv reads HTTPS_PROXY, HTTP_PROXY and NO_PROXY through getenv, each also in lower case where the upper
// case is unset, as net/http does; only the egress client reads them (servers.md rule 30). It returns nil when
// neither proxy is set. A proxy URL with user information is refused: credentials come from a file.
func ProxyFromEnv(getenv func(string) string) (*Proxy, error) {
	lookup := func(name string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return getenv(strings.ToLower(name))
	}
	httpsProxy, err := parseProxyURL("HTTPS_PROXY", lookup("HTTPS_PROXY"))
	if err != nil {
		return nil, err
	}
	httpProxy, err := parseProxyURL("HTTP_PROXY", lookup("HTTP_PROXY"))
	if err != nil {
		return nil, err
	}
	if httpsProxy == nil && httpProxy == nil {
		return nil, nil
	}
	return &Proxy{HTTPS: httpsProxy, HTTP: httpProxy, NoProxy: lookup("NO_PROXY")}, nil
}

// parseProxyURL takes a proxy as http or https URL of host and port, or as host:port, which means http as net/http
// reads it. Its messages name the variable, never its value, which may hold a password.
func parseProxyURL(name, raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a URL", ErrProxy, name)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: %s holds user information; proxy credentials come from a file", ErrProxy, name)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s is not an http or https URL", ErrProxy, name)
	}
	if u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: %s names more than a scheme, a host and a port", ErrProxy, name)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// ParseProxyCredentials reads the content of a proxy credentials file, "user:password" on one line.
func ParseProxyCredentials(content []byte) (*url.Userinfo, error) {
	line := strings.TrimRight(string(content), "\r\n")
	user, password, ok := strings.Cut(line, ":")
	if !ok || user == "" || strings.ContainsAny(line, "\r\n") {
		return nil, fmt.Errorf("%w: the credentials are not user:password on one line", ErrProxy)
	}
	return url.UserPassword(user, password), nil
}

// String says which proxy is in effect, for the reported configuration (servers.md rule 7); never the credentials.
func (p *Proxy) String() string {
	if p == nil {
		return "none"
	}
	describe := func(u *url.URL) string {
		if u == nil {
			return "direct"
		}
		return u.String()
	}
	s := "https via " + describe(p.HTTPS) + ", http via " + describe(p.HTTP)
	if p.NoProxy != "" {
		s += ", no proxy for " + p.NoProxy
	}
	if p.Credentials != nil {
		s += ", with credentials"
	}
	return s
}

// choose is the proxy of r, nil to go direct.
func (p *Proxy) choose(r *http.Request) (*url.URL, error) {
	if p == nil {
		return nil, nil
	}
	proxy := p.HTTPS
	if r.URL.Scheme == "http" {
		proxy = p.HTTP
	}
	if proxy == nil || direct(r.URL, p.NoProxy) {
		return nil, nil
	}
	chosen := *proxy
	chosen.User = p.Credentials
	return &chosen, nil
}

// direct reports whether target is reached without the proxy: a loopback address, "localhost", or an entry of
// noProxy.
func direct(target *url.URL, noProxy string) bool {
	host, port := target.Hostname(), target.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[target.Scheme]
	}
	host = strings.ToLower(host)
	addr, ipErr := netip.ParseAddr(host)
	if host == "localhost" || (ipErr == nil && addr.IsLoopback()) {
		return true
	}
	for entry := range strings.SplitSeq(noProxy, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if ipErr == nil && prefix.Contains(addr) {
				return true
			}
			continue
		}
		name, entryPort := entry, ""
		if h, p, err := net.SplitHostPort(entry); err == nil {
			name, entryPort = h, p
		}
		if entryPort != "" && entryPort != port {
			continue
		}
		if entryAddr, err := netip.ParseAddr(name); err == nil {
			if ipErr == nil && entryAddr == addr {
				return true
			}
			continue
		}
		name = strings.TrimPrefix(name, ".")
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}

// ProxyFromHost is [ProxyFromEnv] with the credentials of the file the variable credentialsPathVar names, as a host
// configures its egress client: getenv and readFile are the host's (os.Getenv, os.ReadFile), so this package reads
// nothing itself. Credentials without a proxy are refused, as they would go nowhere.
func ProxyFromHost(getenv func(string) string, readFile func(string) ([]byte, error), credentialsPathVar string) (*Proxy, error) {
	proxy, err := ProxyFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	path := getenv(credentialsPathVar)
	if path == "" {
		return proxy, nil
	}
	if proxy == nil {
		return nil, fmt.Errorf("%w: %s is set, but no proxy is", ErrProxy, credentialsPathVar)
	}
	content, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrProxy, credentialsPathVar, err)
	}
	if proxy.Credentials, err = ParseProxyCredentials(content); err != nil {
		return nil, fmt.Errorf("%s: %w", credentialsPathVar, err)
	}
	return proxy, nil
}
