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

package tipki

import (
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"strings"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

// Identifiers that are not gemSpec_OID's and so are not in package oid.
var (
	keyUsageExtension    = oid.MustParse("2.5.29.15")
	extKeyUsageExtension = oid.MustParse("2.5.29.37")
	anyExtendedKeyUsage  = oid.MustParse("2.5.29.37.0")

	serverAuth      = oid.MustParse("1.3.6.1.5.5.7.3.1")
	clientAuth      = oid.MustParse("1.3.6.1.5.5.7.3.2")
	emailProtection = oid.MustParse("1.3.6.1.5.5.7.3.4")
	tslSigning      = oid.MustParse("0.4.0.2231.3.0")
)

// containsOID says whether id is listed. An empty id is listed nowhere: Equal holds for two empty
// values, and an unknown certificate type's OID is empty.
func containsOID(list []x509.OID, id x509.OID) bool {
	return !id.Equal(x509.OID{}) && slices.ContainsFunc(list, id.Equal)
}

// dottedOIDs gives ids in dotted form, joined for a message.
func dottedOIDs(ids []x509.OID) string {
	dotted := make([]string, len(ids))
	for i, id := range ids {
		dotted[i] = id.String()
	}
	return strings.Join(dotted, ", ")
}

// formatASN1OID is [oid.Format] for an identifier as encoding/asn1 reads it.
func formatASN1OID(id asn1.ObjectIdentifier) string {
	known, err := x509.OIDFromASN1OID(id)
	if err != nil {
		return id.String()
	}
	return oid.Format(known)
}
