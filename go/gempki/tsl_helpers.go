package gempki

import "crypto/x509"

// TSLSignerCertCandidates returns the certificates announced inside tsl as
// future TSL-Signer-CA trust anchors — every TSPService whose
// ServiceTypeIdentifier equals [ServiceTypeTSLServiceCertChange].
//
// This is the TUC_PKI_013 ("Import TI-Vertrauensanker aus TSL") extraction
// step. Callers should:
//
//  1. Successfully verify tsl's detached signature first
//     (see [VerifyTSLDetachedSignature]).
//  2. Then call this function to pre-stage future trust anchors for the
//     NEXT TSL update.
//
// Calling this on an unverified TSL is a chicken-and-egg violation —
// the announced anchor would be attacker-supplied. The function does not
// itself verify anything; ordering is the caller's responsibility.
//
// Returns nil for a nil or signature-less TSL. Order matches document order.
func TSLSignerCertCandidates(tsl *TrustServiceStatusList) []*x509.Certificate {
	if tsl == nil {
		return nil
	}
	var out []*x509.Certificate
	for i := range tsl.TrustServiceProviderList {
		prov := &tsl.TrustServiceProviderList[i]
		for j := range prov.TSPServices {
			info := &prov.TSPServices[j].ServiceInformation
			if info.ServiceTypeIdentifier != ServiceTypeTSLServiceCertChange {
				continue
			}
			cert := info.ServiceDigitalIdentity.DigitalId.X509Certificate
			if cert == nil {
				continue
			}
			out = append(out, cert)
		}
	}
	return out
}

// X509FromTSL pairs a TSL-sourced intermediate CA certificate with the
// status metadata the TSL carries for it. The Cert is what callers feed
// into chain building; the ServiceStatus is informational — TI consumers
// typically only trust certs in "granted" status, but enforcing that is
// the caller's call.
type X509FromTSL struct {
	Cert          *x509.Certificate
	ServiceStatus string
}

// OCSPRespondersFromTSL returns every OCSP responder certificate the TSL
// lists (TSPServices with ServiceTypeIdentifier =
// [ServiceTypeCertstatusOcsp]).
//
// Per gemSpec_PKI §6 / TUC_PKI_006 the TSL is the authoritative directory
// of OCSP signers for the TI. The gemLibPki reference implementation
// (de.gematik.pki.gemlibpki.ocsp.OcspResponderValidator) follows the
// same pattern: the embedded OCSP responder cert is authorized iff it
// matches a TSL Certstatus/OCSP TSPService entry. A responder that
// appears here is trusted to answer for the CAs configured under the
// same Trust Service Provider, even when it isn't issued by the same CA
// as the cert under check — TI's KOMP-CAxx responders routinely answer
// for SMCB-CAxx cards, which this entry-based authorization sanctions.
//
// Callers verifying OCSP responses should match the embedded responder
// cert against this list (by SKI) and accept it on match without
// insisting on the responder being signed by the cert's own issuer.
func OCSPRespondersFromTSL(tsl *TrustServiceStatusList) []*X509FromTSL {
	if tsl == nil {
		return nil
	}
	out := make([]*X509FromTSL, 0, 16)
	for i := range tsl.TrustServiceProviderList {
		prov := &tsl.TrustServiceProviderList[i]
		for j := range prov.TSPServices {
			info := &prov.TSPServices[j].ServiceInformation
			if info.ServiceTypeIdentifier != ServiceTypeCertstatusOcsp {
				continue
			}
			cert := info.ServiceDigitalIdentity.DigitalId.X509Certificate
			if cert == nil {
				continue
			}
			out = append(out, &X509FromTSL{
				Cert:          cert,
				ServiceStatus: info.ServiceStatus,
			})
		}
	}
	return out
}

// IntermediateCAsFromTSL returns every CA/PKC service certificate the TSL
// lists — the candidate intermediates a [Validator] can be fed alongside
// an end-entity. Order is the document order from the TSL XML.
//
// Each returned cert was already parsed (and brainpool-handled) by
// [ParseTSL]; callers can pass them straight to [Validator.Validate] or
// [BuildChain] as the intermediates slice.
func IntermediateCAsFromTSL(tsl *TrustServiceStatusList) []*X509FromTSL {
	if tsl == nil {
		return nil
	}
	out := make([]*X509FromTSL, 0, 32)
	// Index-based iteration to avoid copying the large TSL provider/service
	// structs on each loop step.
	for i := range tsl.TrustServiceProviderList {
		prov := &tsl.TrustServiceProviderList[i]
		for j := range prov.TSPServices {
			info := &prov.TSPServices[j].ServiceInformation
			if info.ServiceTypeIdentifier != ServiceTypeCaPkc {
				continue
			}
			cert := info.ServiceDigitalIdentity.DigitalId.X509Certificate
			if cert == nil {
				continue
			}
			out = append(out, &X509FromTSL{
				Cert:          cert,
				ServiceStatus: info.ServiceStatus,
			})
		}
	}
	return out
}
