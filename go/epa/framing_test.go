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

package epa

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/epa/vau"
)

// Server rule 28, "Headers": a chunked request reaches the Aktensystem framed by its exact Content-Length,
// without the client's framing or hop-by-hop headers, so its body cannot carry a second request (RFC 9112
// Section 6.3).
func TestServerRule28_AChunkedRequestIsFramedByItsLengthInsideTheVAU(t *testing.T) {
	inner := make(chan []byte, 1)
	vauServer, err := vau.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	vauServer.Inner = func(raw []byte) { inner <- bytes.Clone(raw) }
	aktensystem := httptest.NewServer(vauServer)
	defer aktensystem.Close()
	channel, err := vau.OpenChannel(aktensystem.URL, vau.EnvNonPU, aktensystem.Client())
	if err != nil {
		t.Fatal(err)
	}
	provider := AllProviders[0]
	p := &Proxy{
		sessionManager:  &sessionManager{sessions: map[ProviderNumber]*Session{provider: {VAUChannel: channel}}},
		maxRequestBytes: DefaultMaxRequestBytes,
	}
	var framing []string
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		framing = r.TransferEncoding
		r.SetPathValue("providerNumber", strconv.Itoa(int(provider)))
		p.HandleForwardToVAUProvider(w, r)
	}))
	defer front.Close()

	const smuggled = "POST /epa/x HTTP/1.1\r\nHost: vau\r\nContent-Length: 0\r\n\r\n"
	body := "first" + smuggled
	// A reader of unknown length makes the client send the body chunked.
	req, err := http.NewRequest(http.MethodPost, front.URL+"/providers/"+strconv.Itoa(int(provider))+"/vau/epa/xds-document/api/I_Document_Management_Insurant", io.MultiReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "the client's connection only")
	req.Header.Set("Keep-Alive", "timeout=5")
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(framing) != 1 || framing[0] != "chunked" {
		t.Fatalf("the proxy did not receive the body chunked: %v", framing)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	raw := <-inner
	reader := bufio.NewReader(bytes.NewReader(raw))
	got, err := http.ReadRequest(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentLength != int64(len(body)) || len(got.TransferEncoding) != 0 {
		t.Errorf("framing: Content-Length %d, Transfer-Encoding %v", got.ContentLength, got.TransferEncoding)
	}
	gotBody, err := io.ReadAll(got.Body)
	if err != nil || string(gotBody) != body {
		t.Errorf("body = %q, %v", gotBody, err)
	}
	if rest, _ := io.ReadAll(reader); len(rest) != 0 {
		t.Errorf("bytes after the inner request: %q", rest)
	}
	for _, name := range []string{"Connection", "X-Hop", "Keep-Alive", "Transfer-Encoding"} {
		if got.Header.Get(name) != "" {
			t.Errorf("the inner request carries %s", name)
		}
	}
}

// The channel itself never sends a request whose length is unknown, whoever builds it.
func TestServerRule28_TheVAUChannelRefusesARequestWithoutAKnownLength(t *testing.T) {
	vauServer, err := vau.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	aktensystem := httptest.NewServer(vauServer)
	defer aktensystem.Close()
	channel, err := vau.OpenChannel(aktensystem.URL, vau.EnvNonPU, aktensystem.Client())
	if err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func(*http.Request){
		"unknown length": func(r *http.Request) { r.ContentLength = -1 },
		"chunked":        func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"body, length 0": func(r *http.Request) { r.ContentLength = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/epa/x", strings.NewReader("body"))
			if err != nil {
				t.Fatal(err)
			}
			build(req)
			if _, err := channel.EncryptRequest(req); !errors.Is(err, vau.ErrRequestFraming) {
				t.Errorf("err = %v", err)
			}
		})
	}
}
