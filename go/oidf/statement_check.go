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

package oidf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// maxStatementBytes bounds the payload the relying party signs: what a hook adds cannot grow the statement past what
// a federation member reading it is prepared to take.
const maxStatementBytes = 64 << 10

// informationalName is the Wertebereich of client_name and organization_name in gemSpec_IDP_FD A_23034-02 Tabelle 4,
// ^[ à-üÀ-Ü ß\w\ \-\.\+\*\/]{1,128}$, taken as written: \w is ASCII in RE2 as in Java, the ranges are those of
// Latin-1, and the length counts characters.
var informationalName = regexp.MustCompile(`^[ à-üÀ-Üß\w\-.+*/]{1,128}$`)

// idTokenVersions are the values of id_token_version_supported that gemSpec_IDP_FD A_27505 allows.
var idTokenVersions = []string{"1.0.0", "2.0.0"}

// checkStatement refuses a statement that others could not take for this relying party's entity configuration. Its
// jwks holds the signing key only (gemSpec_IDP_FD A_23034-02 Tabelle 3: "nur die öffentlichen Schlüssel zu
// Schlüsseln, mit den das Entity Statement signiert ist"), and its openid_relying_party metadata is as Tabelle 4 and
// A_27505 require. The checks run after the hooks, at every signing, so a hook may supply what the configuration leaves
// out; for New's first signing, which only RelyingPartyConfig.Hooks take part in, such a member has to come from them.
func (rp *RelyingParty) checkStatement(es *EntityStatement) error {
	if es.Issuer == "" || es.Issuer != es.Subject {
		return fmt.Errorf("%w: iss and sub differ", ErrEntityStatement)
	}
	if es.Jwks == nil || es.Jwks.Keys == nil {
		return fmt.Errorf("%w: no jwks", ErrEntityStatement)
	}
	if err := checkPublicKeys(es.Jwks.Keys, "jwks"); err != nil {
		return err
	}
	keys := es.Jwks.Keys.Keys
	if len(keys) != 1 || keys[0].KeyID != rp.keys.SignKID {
		return fmt.Errorf("%w: jwks holds another key than the signing key", ErrEntityStatement)
	}
	public, ok := keys[0].Key.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || isNil(rp.keys.Sign) || !public.Equal(rp.keys.Sign.Public()) {
		return fmt.Errorf("%w: jwks holds another key under the signing key's kid", ErrEntityStatement)
	}
	if es.Metadata == nil || es.Metadata.OpenidRelyingParty == nil {
		return fmt.Errorf("%w: no openid_relying_party metadata", ErrEntityStatement)
	}
	// gematik's Fachdienst registration tests (FEDM_FD_REG_003, FEDM_FD_REG_004) read metadata.federation_entity, and
	// an empty one would name nobody.
	if entity := es.Metadata.FederationEntity; entity == nil || entity.Name == "" && entity.OrganizationName == "" {
		return fmt.Errorf("%w: federation_entity names neither name nor organization_name", ErrEntityStatement)
	}
	return checkRelyingPartyMetadata(es.Metadata.OpenidRelyingParty)
}

// checkRelyingPartyMetadata refuses openid_relying_party metadata without what gemSpec_IDP_FD A_23034-02 Tabelle 4
// and A_27505 require of a registered relying party. The content of keywords and contacts is the deployment's; only
// their presence is checked.
func checkRelyingPartyMetadata(metadata *OpenIDRelyingPartyMetadata) error {
	// Tabelle 4 (*): "darf der Metadatenblock nur entweder signed_jwks_uri oder jwks enthalten".
	if (metadata.Jwks == nil) == (metadata.SignedJwksURI == "") {
		return fmt.Errorf("%w: openid_relying_party needs exactly one of jwks and signed_jwks_uri", ErrEntityStatement)
	}
	if metadata.Jwks != nil {
		if err := checkPublicKeys(metadata.Jwks.Keys, "openid_relying_party jwks"); err != nil {
			return err
		}
	}
	for _, uri := range metadata.RedirectURIs {
		if err := checkRegisteredRedirectURI(uri); err != nil {
			return err
		}
	}
	if !informationalName.MatchString(metadata.ClientName) {
		return fmt.Errorf("%w: client_name is not as Tabelle 4 allows", ErrEntityStatement)
	}
	if !informationalName.MatchString(metadata.OrganizationName) {
		return fmt.Errorf("%w: organization_name is not as Tabelle 4 allows", ErrEntityStatement)
	}
	for _, prefix := range []string{"product_type:", "product_type_version:"} {
		if !slices.ContainsFunc(metadata.Keywords, func(keyword string) bool {
			value, found := strings.CutPrefix(keyword, prefix)
			return found && value != ""
		}) {
			return fmt.Errorf("%w: keywords lack %s", ErrEntityStatement, prefix)
		}
	}
	if !slices.ContainsFunc(metadata.Contacts, func(contact string) bool { return contact != "" }) {
		return fmt.Errorf("%w: contacts lack a support address", ErrEntityStatement)
	}
	return checkTIFeatures(metadata.TIFeaturesSupported)
}

// maxRedirectURIBytes bounds a redirect URI the relying party registers.
const maxRedirectURIBytes = 2048

// checkRegisteredRedirectURI holds a redirect URI of the statement to gemSpec_IDP_FD A_27585: "alle im Entity
// Statement unter dem Claim "redirect_uris" aufgeführten URIs: gültige HTTPS-URLs sind, keinen query part enthalten,
// keinen fragment part enthalten, keine Nutzer-spezifischen Anmeldeinformationen enthalten." Beyond that, it is
// printable ASCII within maxRedirectURIBytes, since logins compare it byte for byte.
func checkRegisteredRedirectURI(uri string) error {
	if len(uri) > maxRedirectURIBytes {
		return fmt.Errorf("%w: a redirect_uri is longer than %d characters", ErrEntityStatement, maxRedirectURIBytes)
	}
	for _, c := range []byte(uri) {
		if c <= 0x20 || c >= 0x7f {
			return fmt.Errorf("%w: a redirect_uri holds a character outside printable ASCII", ErrEntityStatement)
		}
	}
	rest, found := strings.CutPrefix(uri, "https://")
	host, _, _ := strings.Cut(rest, "/")
	if !found || host == "" || strings.HasPrefix(host, ":") {
		return fmt.Errorf("%w: a redirect_uri is no https URL with a host (A_27585)", ErrEntityStatement)
	}
	if strings.ContainsAny(uri, "?#") || strings.Contains(host, "@") {
		return fmt.Errorf("%w: a redirect_uri has a query, a fragment or user info (A_27585)", ErrEntityStatement)
	}
	return nil
}

// checkTIFeatures refuses a ti_features_supported member that names no ID token version, one A_27505 does not allow,
// or one twice.
func checkTIFeatures(features *TIFeatures) error {
	if features == nil || len(features.IDTokenVersionSupported) == 0 {
		return fmt.Errorf("%w: ti_features_supported names no id_token_version_supported", ErrEntityStatement)
	}
	versions := features.IDTokenVersionSupported
	for i, version := range versions {
		if !slices.Contains(idTokenVersions, version) {
			return fmt.Errorf("%w: id_token_version_supported holds a version A_27505 does not allow", ErrEntityStatement)
		}
		if slices.Contains(versions[:i], version) {
			return fmt.Errorf("%w: id_token_version_supported holds a version twice", ErrEntityStatement)
		}
	}
	return nil
}

// checkPublicKeys refuses a key set with a private key, or with a key that is not EC on P-256, the only keys
// A_23196 allows a relying party.
func checkPublicKeys(set *jose.JSONWebKeySet, where string) error {
	if set == nil {
		return fmt.Errorf("%w: %s holds no keys", ErrEntityStatement, where)
	}
	for _, key := range set.Keys {
		if !key.IsPublic() {
			return fmt.Errorf("%w: %s holds a private key", ErrEntityStatement, where)
		}
		public, ok := key.Key.(*ecdsa.PublicKey)
		if !ok || public.Curve != elliptic.P256() {
			return fmt.Errorf("%w: %s holds a key that is no P-256 key", ErrEntityStatement, where)
		}
	}
	return nil
}
