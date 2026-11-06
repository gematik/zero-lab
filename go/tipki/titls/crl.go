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

package titls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"time"
)

var (
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidAuthorityKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidInvalidityDate           = asn1.ObjectIdentifier{2, 5, 29, 24}
)

// crlSignatures are the signatures a CRL may carry: those of a web path (TLSV-023). crypto/x509 checks a
// CRL's signature with SHA-1 allowed, so the algorithm is held to this list first.
var crlSignatures = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
	x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
	x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
}

// crlStatus is what the DER CRL fetched from url says about leaf (TLSV-044). It counts (ok) only when
// issuer signed it with an allowed algorithm, now lies in [thisUpdate, nextUpdate), and it is a complete CRL
// for end entities covering url; a CRL with a critical extension it does not know, a delta CRL among them,
// does not count.
func crlStatus(der []byte, url string, leaf, issuer *x509.Certificate, now time.Time) (revoked bool, nextUpdate time.Time, ok bool) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return false, time.Time{}, false
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) || !slices.Contains(crlSignatures, crl.SignatureAlgorithm) {
		return false, time.Time{}, false
	}
	if crl.CheckSignatureFrom(issuer) != nil {
		return false, time.Time{}, false
	}
	if crl.NextUpdate.IsZero() || crl.ThisUpdate.After(now) || !now.Before(crl.NextUpdate) {
		return false, time.Time{}, false
	}
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidIssuingDistributionPoint):
			if !coversEndEntity(ext.Value, url) {
				return false, time.Time{}, false
			}
		case ext.Critical && !ext.Id.Equal(oidCRLNumber) && !ext.Id.Equal(oidAuthorityKeyIdentifier):
			return false, time.Time{}, false
		}
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if slices.ContainsFunc(entry.Extensions, func(ext pkix.Extension) bool {
			return ext.Critical && !ext.Id.Equal(oidReasonCode) && !ext.Id.Equal(oidInvalidityDate)
		}) {
			// An entry extension such as certificateIssuer changes whom the entry is about; one not
			// understood leaves the list unread.
			return false, time.Time{}, false
		}
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return true, crl.NextUpdate, true
		}
	}
	return false, crl.NextUpdate, true
}

type issuingDistributionPoint struct {
	DistributionPoint          distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString        `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

// coversEndEntity reads an issuingDistributionPoint (RFC 5280 §5.2.5): the CRL covers an end entity's
// status from url unless it is limited to CAs or attribute certificates, to some reasons, is indirect, or
// names its distribution point other than by url.
func coversEndEntity(value []byte, url string) bool {
	var idp issuingDistributionPoint
	if rest, err := asn1.Unmarshal(value, &idp); err != nil || len(rest) > 0 {
		return false
	}
	if idp.OnlyContainsCACerts || idp.OnlyContainsAttributeCerts || idp.IndirectCRL || idp.OnlySomeReasons.BitLength > 0 {
		return false
	}
	if len(idp.DistributionPoint.RelativeName) > 0 {
		return false
	}
	if len(idp.DistributionPoint.FullName) == 0 {
		return true
	}
	return slices.ContainsFunc(idp.DistributionPoint.FullName, func(name asn1.RawValue) bool {
		// GeneralName uniformResourceIdentifier [6] IA5String.
		return name.Class == asn1.ClassContextSpecific && name.Tag == 6 && string(name.Bytes) == url
	})
}
