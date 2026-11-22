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

package idpd

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// marker stands for the IDP-Dienst's text; an error that holds it carries that text into a log (servers.md rule 14).
const marker = "PEER-INPUT-7f3a"

// requireRefusedFor asserts err refuses for its fixed reason and quotes nothing of the IDP-Dienst.
func requireRefusedFor(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("the error quotes the IDP-Dienst: %v", err)
	}
	if err.Error() != reason {
		t.Fatalf("got %v, want %q", err, reason)
	}
}

// Server rule 14: the IDP-Dienst's error, in a body or a redirect, is named by its status and a gematik_code of
// digits; error, gematik_error_text and a gematik_code of another form stay in the fields.
func TestServerRule14_AnIDPDienstErrorIsNotQuoted(t *testing.T) {
	body := `{"error":"` + marker + `","gematik_error_text":"` + marker + `","gematik_code":"2012"}`
	err := parseErrorResponse(http.StatusBadRequest, strings.NewReader(body))
	requireRefusedFor(t, err, "IDP-Dienst refused with status 400, gematik_code 2012")
	if typed, ok := errors.AsType[*Error](err); !ok || typed.GematikErrorText != marker {
		t.Errorf("the typed error lost its text: %v", err)
	}
	requireRefusedFor(t, parseErrorResponse(http.StatusBadRequest, strings.NewReader(marker)), "IDP-Dienst refused with status 400; its error does not decode")
	requireRefusedFor(t, parseErrorResponse(http.StatusBadRequest, strings.NewReader(`{"gematik_code":"`+marker+`"}`)), "IDP-Dienst refused with status 400")
	location := &url.URL{RawQuery: url.Values{"error": {marker}, "gematik_error_text": {marker}, "gematik_code": {marker}}.Encode()}
	requireRefusedFor(t, refusalOf(location), "IDP-Dienst refused")
}

// Server rule 14: answers that do not decode are named, not quoted; a member named twice still unwraps.
func TestServerRule14_AnUndecodableAnswerIsNotQuoted(t *testing.T) {
	_, err := unmarshalTokenResponse(strings.NewReader(`{"` + marker + `":1,"` + marker + `":2}`))
	requireRefusedFor(t, err, "token response: does not decode")
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Errorf("got %v, want a duplicate name to unwrap", err)
	}
}

// Server rule 14: an encrypted token of another alg is refused without go-jose's quote of the header.
func TestServerRule14_AnEncryptedTokenOfAnotherAlgIsNotQuoted(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	token := enc([]byte(`{"alg":"`+marker+`","enc":"`+marker+`"}`)) + ".." + enc([]byte("iv")) + "." + enc([]byte("ct")) + "." + enc([]byte("tag"))
	_, err := decryptToken(token, make([]byte, 32))
	requireRefusedFor(t, err, "decrypting token: no compact JWE of dir and A256GCM")
}

// Server rule 14: an error code RFC 6749 registers is named in the error text, as pep/proxy names it; any other is
// not.
func TestServerRule14_AnIDPDienstErrorNamesARegisteredCodeOnly(t *testing.T) {
	err := parseErrorResponse(http.StatusBadRequest, strings.NewReader(`{"error":"invalid_client","gematik_code":"2012"}`))
	requireRefusedFor(t, err, "IDP-Dienst refused with status 400, error invalid_client, gematik_code 2012")
}
