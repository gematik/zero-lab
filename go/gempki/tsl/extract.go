package tsl

import "crypto/x509"

// ServiceCert is a certificate the TSL publishes for one of its services,
// with the status the TSL carries for it. TI consumers typically act only
// on "granted" services; enforcing that is the caller's call.
type ServiceCert struct {
	Cert          *x509.Certificate
	ServiceStatus string
}

// IntermediateCAs returns every CA/PKC service certificate in document
// order — the candidate intermediates a [gempki.Validator] is fed alongside
// an end entity.
func IntermediateCAs(list *List) []*ServiceCert {
	return serviceCerts(list, ServiceTypeCaPkc)
}

// OCSPResponders returns every OCSP responder certificate the TSL lists.
//
// Per gemSpec_PKI §6 / TUC_PKI_006 the TSL is the authoritative directory
// of OCSP signers for the TI, and gemLibPki authorizes an embedded responder
// certificate iff it matches one of these entries. A responder listed here
// may answer for CAs it was not issued by — TI's KOMP-CAxx responders
// routinely answer for SMCB-CAxx cards — which is why
// [gempki.OCSPChecker.TSLResponders] exists.
func OCSPResponders(list *List) []*ServiceCert {
	return serviceCerts(list, ServiceTypeCertstatusOcsp)
}

func serviceCerts(list *List, serviceType string) []*ServiceCert {
	if list == nil {
		return nil
	}
	var out []*ServiceCert
	for i := range list.TrustServiceProviderList {
		prov := &list.TrustServiceProviderList[i]
		for j := range prov.TSPServices {
			info := &prov.TSPServices[j].ServiceInformation
			if info.ServiceTypeIdentifier != serviceType {
				continue
			}
			if cert := info.ServiceDigitalIdentity.DigitalId.X509Certificate; cert != nil {
				out = append(out, &ServiceCert{Cert: cert, ServiceStatus: info.ServiceStatus})
			}
		}
	}
	return out
}
