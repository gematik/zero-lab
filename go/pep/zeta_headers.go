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

package pep

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
)

// The headers a ZETA PEP HTTP proxy puts into the request it forwards (gemSpec_ZETA A_25669-01). A request
// that carries one of them from the client loses it: the proxy is the only source.
const (
	HeaderZETAUserInfo    = "Zeta-User-Info"
	HeaderZETAClientData  = "Zeta-Client-Data"
	HeaderZETAPoPPContent = "Zeta-Popp-Token-Content"
)

// ZETAHeaderNames are the headers of A_25669-01, which a proxy removes from the client's request.
func ZETAHeaderNames() []string {
	return []string{HeaderZETAUserInfo, HeaderZETAClientData, HeaderZETAPoPPContent}
}

// zetaUserInfo is zeta-user-info.yaml of the gematik ZETA schemas.
type zetaUserInfo struct {
	Identifier       string `json:"identifier"`
	ProfessionOID    string `json:"professionOID"`
	CommonName       string `json:"commonName"`
	OrganizationName string `json:"organizationName,omitempty"`
}

// zetaClientData is client-data.yaml of the gematik ZETA schemas.
type zetaClientData struct {
	ClientID       string `json:"client_id"`
	ProductID      string `json:"product_id"`
	ProductVersion string `json:"product_version"`
	Platform       string `json:"platform,omitempty"`
}

// zetaClaims are the access token's claims the two headers are made of. The token names its holder in sub, as
// the ZETA access token schema and the authorization server have it; Tabelle 15 of A_26589-01 calls that claim
// identifier.
type zetaClaims struct {
	Subject          string `json:"sub"`
	ProfessionOID    string `json:"profession_oid"`
	CommonName       string `json:"common_name"`
	OrganizationName string `json:"organization_name"`
	ClientID         string `json:"client_id"`
	ProductID        string `json:"product_id"`
	ProductVersion   string `json:"product_version"`
	Platform         string `json:"platform"`
}

// The descriptions are fixed and name no claim value (server rule 14).
var (
	errZETAUserInfoClaims   = errors.New("zeta-user-info: the token lacks sub, profession_oid or common_name")
	errZETAClientDataClaims = errors.New("zeta-client-data: the token lacks client_id, product_id or product_version")
)

// ZETAUserInfo is the value of zeta-user-info for the request ctx let through (A_26589-01): the user data of
// the verified token's claims as Base64-URL encoded JSON. It is an error when the claims lack a member the
// schema requires.
func ZETAUserInfo(ctx Context) (string, error) {
	c, err := zetaClaimsOf(ctx)
	if err != nil {
		return "", err
	}
	if c.Subject == "" || c.ProfessionOID == "" || c.CommonName == "" {
		return "", errZETAUserInfoClaims
	}
	return zetaHeaderValue(zetaUserInfo{
		Identifier:       c.Subject,
		ProfessionOID:    c.ProfessionOID,
		CommonName:       c.CommonName,
		OrganizationName: c.OrganizationName,
	})
}

// ZETAClientData is the value of zeta-client-data for the request ctx let through (A_26590-02): the client
// data of the verified token's claims as Base64-URL encoded JSON. The platform is named only when it is one
// the schema knows.
func ZETAClientData(ctx Context) (string, error) {
	c, err := zetaClaimsOf(ctx)
	if err != nil {
		return "", err
	}
	if c.ClientID == "" || c.ProductID == "" || c.ProductVersion == "" {
		return "", errZETAClientDataClaims
	}
	data := zetaClientData{ClientID: c.ClientID, ProductID: c.ProductID, ProductVersion: c.ProductVersion}
	switch c.Platform {
	case "android", "apple", "windows", "linux":
		data.Platform = c.Platform
	}
	return zetaHeaderValue(data)
}

func zetaClaimsOf(ctx Context) (zetaClaims, error) {
	var c zetaClaims
	err := ctx.UnmarshalClaims(&c)
	return c, err
}

// zetaHeaderValue encodes with padding, as gematik's reference PEP does (RFC 4648 Section 5).
func zetaHeaderValue(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(raw), nil
}
