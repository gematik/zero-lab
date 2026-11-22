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
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha256" // the hashes of certHashAlgorithms
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// responderClockTolerance is the skew allowed between a delegated responder's validity and our clock.
const responderClockTolerance = 37500 * time.Millisecond

var oidCertHash = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 13}

// revocation is TLSV-044: the stapled OCSP response, the responder, the CRL, in that order; the first
// status decides, and without one the server is accepted with [WarningRevocationUnavailable].
func revocation(ctx context.Context, leaf, issuer *x509.Certificate, stapled []byte, now time.Time, fetch Fetcher) Verdict {
	answer := func(der []byte) (Verdict, bool) {
		status, nextUpdate, ok := ocspStatus(der, leaf, issuer, now)
		if !ok {
			return Verdict{}, false
		}
		switch status {
		case ocsp.Good:
			return accepted(leaf, now, nextUpdate), true
		case ocsp.Revoked:
			return refuse(Revoked, "revoked (OCSP)"), true
		}
		return Verdict{}, false
	}
	if len(stapled) > 0 {
		if verdict, ok := answer(stapled); ok {
			return verdict
		}
	}
	if fetch == nil {
		fetch = Offline{}
	}
	// RFC 5019's SHA-1 CertID, without a nonce: what public responders answer from their caches.
	if request, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1}); err == nil {
		for _, url := range leaf.OCSPServer {
			if der, err := fetch.OCSP(ctx, url, request); err == nil {
				if verdict, ok := answer(der); ok {
					return verdict
				}
			}
		}
	}
	for _, url := range leaf.CRLDistributionPoints {
		der, err := fetch.CRL(ctx, url)
		if err != nil {
			continue
		}
		if revoked, nextUpdate, ok := crlStatus(der, url, leaf, issuer, now); ok {
			if revoked {
				return refuse(Revoked, "revoked (CRL)")
			}
			return accepted(leaf, now, nextUpdate)
		}
	}
	// TLSV-044's deviation: accepted without a status. It rests on none, so it is not reused (TLSV-050)
	// and the next connection asks the sources again.
	return Verdict{
		Code:     Valid,
		Detail:   "valid without a revocation status: no source gave one",
		Warnings: []string{WarningRevocationUnavailable},
	}
}

// ocspStatus is what the DER OCSP response says about leaf (TLSV-044). It counts (ok) only when the issuer
// signed it, or a responder the issuer certified directly for OCSP signing that is valid now (RFC 6960
// §4.2.2.2), with an algorithm a web path may carry (TLSV-023); when now lies in [thisUpdate, nextUpdate]; and
// when a certHash extension, where present, names leaf. golang.org/x/crypto/ocsp parses the response and finds
// leaf's serial; the responder's authorization and the signature are checked here, as the package admits SHA-1
// signatures and asks nothing of a delegate but the issuer's signature.
func ocspStatus(der []byte, leaf, issuer *x509.Certificate, now time.Time) (status int, nextUpdate time.Time, ok bool) {
	response, err := ocsp.ParseResponseForCert(der, leaf, nil)
	if err != nil {
		return 0, time.Time{}, false
	}
	signer := issuer
	if delegate := response.Certificate; delegate != nil && !sameEntity(delegate, issuer) {
		if !authorizedDelegate(delegate, issuer, now) {
			return 0, time.Time{}, false
		}
		signer = delegate
	}
	if !slices.Contains(crlSignatures, response.SignatureAlgorithm) ||
		signer.CheckSignature(response.SignatureAlgorithm, response.TBSResponseData, response.Signature) != nil {
		return 0, time.Time{}, false
	}
	at := now.Truncate(time.Second)
	if response.ThisUpdate.After(at) || (!response.NextUpdate.IsZero() && response.NextUpdate.Before(at)) {
		return 0, time.Time{}, false
	}
	if response.Status != ocsp.Unknown && !certHashMatches(response, leaf) {
		return 0, time.Time{}, false
	}
	return response.Status, response.NextUpdate, true
}

// sameEntity says whether cert is issuer itself: the same name and key.
func sameEntity(cert, issuer *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, issuer.RawSubject) && bytes.Equal(cert.RawSubjectPublicKeyInfo, issuer.RawSubjectPublicKeyInfo)
}

// authorizedDelegate is RFC 6960 §4.2.2.2: certified by issuer itself, for id-kp-OCSPSigning, and valid now.
func authorizedDelegate(delegate, issuer *x509.Certificate, now time.Time) bool {
	if !bytes.Equal(delegate.RawIssuer, issuer.RawSubject) || delegate.CheckSignatureFrom(issuer) != nil {
		return false
	}
	if !slices.Contains(delegate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return false
	}
	return !now.Add(responderClockTolerance).Before(delegate.NotBefore) && !now.Add(-responderClockTolerance).After(delegate.NotAfter)
}

// certHashMatches checks the TI's certHash extension where a responder adds one; the web profile does not
// require it, but one present must name leaf.
func certHashMatches(response *ocsp.Response, leaf *x509.Certificate) bool {
	for _, extension := range response.Extensions {
		if !extension.Id.Equal(oidCertHash) {
			continue
		}
		var value struct {
			Algorithm struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			Hash []byte
		}
		if rest, err := asn1.Unmarshal(extension.Value, &value); err != nil || len(rest) > 0 {
			return false
		}
		hash, known := certHashAlgorithms[value.Algorithm.Algorithm.String()]
		if !known {
			return false
		}
		digest := hash.New()
		digest.Write(leaf.Raw)
		return bytes.Equal(digest.Sum(nil), value.Hash)
	}
	return true
}

var certHashAlgorithms = map[string]crypto.Hash{
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// accepted is a valid verdict, reusable until the earliest of notAfter, the status's nextUpdate and
// MaxStatusReuse from now (TLSV-050, TLSV-051).
func accepted(leaf *x509.Certificate, now time.Time, nextUpdate time.Time) Verdict {
	until := now.Add(MaxStatusReuse)
	if leaf.NotAfter.Before(until) {
		until = leaf.NotAfter
	}
	if !nextUpdate.IsZero() && nextUpdate.Before(until) {
		until = nextUpdate
	}
	return Verdict{Code: Valid, Detail: "valid", ReusableUntil: until}
}
