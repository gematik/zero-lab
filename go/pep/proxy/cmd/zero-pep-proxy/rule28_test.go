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

package main

import (
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// Server rule 28, limits before work: the server bounds the request line and header itself, below Go's default
// of 1 MiB. A request within the limit reaches the handler; one above it is answered 431 and does not.
func TestServerRule28_ARequestHeaderAboveTheLimitIsRefusedBeforeTheHandler(t *testing.T) {
	reached := 0
	srv := newHTTPServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))
	if srv.MaxHeaderBytes != maxHeaderBytes || srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("MaxHeaderBytes = %d, ReadHeaderTimeout = %s", srv.MaxHeaderBytes, srv.ReadHeaderTimeout)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	send := func(headerBytes int) int {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.Addr().String()+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Filler", strings.Repeat("a", headerBytes))
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if status := send(maxHeaderBytes / 2); status != http.StatusOK || reached != 1 {
		t.Errorf("within the limit: status %d, handler reached %d times", status, reached)
	}
	// net/http reads 4096 bytes beyond MaxHeaderBytes before it refuses.
	if status := send(maxHeaderBytes + 8192); status != http.StatusRequestHeaderFieldsTooLarge || reached != 1 {
		t.Errorf("above the limit: status %d, handler reached %d times", status, reached)
	}
}

// Server rule 28, headers: the names the server answers for come from its configuration: the host of its public
// URL as the URL has it, and what PEP_HOSTS adds. What is no host name is refused at start.
func TestServerRule28_TheServedHostsComeFromTheConfiguration(t *testing.T) {
	for name, c := range map[string]struct {
		publicURL, more string
		want            []string
	}{
		"the public host":            {"https://pep.example", "", []string{"pep.example"}},
		"with its port":              {"http://localhost:8080", "", []string{"localhost:8080"}},
		"more names":                 {"https://pep.example", "pep.internal:4180, pep", []string{"pep.example", "pep.internal:4180", "pep"}},
		"a name twice":               {"https://pep.example", "pep.example,,", []string{"pep.example"}},
		"no host in the public URL":  {"/oauth2", "", nil},
		"a URL among the more names": {"https://pep.example", "https://pep.internal", nil},
		"a path among them":          {"https://pep.example", "pep.internal/x", nil},
	} {
		got, err := servedHosts(c.publicURL, c.more)
		if (err == nil) != (c.want != nil) || !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, %v; want %q", name, got, err, c.want)
		}
	}
}
