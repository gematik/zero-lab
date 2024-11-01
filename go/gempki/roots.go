package gempki

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

type TimeWithoutTimezone struct {
	time.Time
}

func (t *TimeWithoutTimezone) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	tt, err := time.Parse("2006-01-02T15:04:05", str)
	if err != nil {
		return err
	}
	t.Time = tt
	return nil
}

type Root struct {
	Cert           *x509.Certificate   `json:"-"`
	CertRaw        []byte              `json:"cert,base64"`
	CommonName     string              `json:"cn"`
	Name           string              `json:"name"`
	Next           string              `json:"next"`
	NotValidAfter  TimeWithoutTimezone `json:"nva"`
	NotValidBefore TimeWithoutTimezone `json:"nvb"`
	Prev           string              `json:"prev"`
	SubjectKeyID   string              `json:"ski"`
}

func (r *Root) UnmarshalJSON(data []byte) error {
	type Alias Root
	var root Alias
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	cert, err := brainpool.ParseCertificate(root.CertRaw)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	root.Cert = cert

	*r = Root(root)
	return nil
}

type Roots struct {
	ByCommonName map[string]Root
}

func (r Roots) BuildCertPool(tsl *TrustServiceStatusList) *x509.CertPool {
	rootCAs := x509.NewCertPool()
	// add all CA certificates from TSL which were issued by the roots
	for _, provider := range tsl.TrustServiceProviderList {
		for _, service := range provider.TSPServices {
			if service.ServiceInformation.ServiceTypeIdentifier == Svctype_CA_PKC {
				caCert := service.ServiceInformation.ServiceDigitalIdentity.DigitalId.X509Certificate
				root, ok := r.ByCommonName[caCert.Issuer.CommonName]
				if !ok {
					slog.Debug("CA certificate not issued any known root", "ca", caCert.Subject.CommonName)
					continue
				}
				if err := caCert.CheckSignatureFrom(root.Cert); err != nil {
					slog.Error("CA certificate not signed by root", "ca", caCert.Subject.CommonName, "root", root.Cert.Subject.CommonName)
					continue
				}
				// check if the CA certificate was issued by the matching root
				rootCAs.AddCert(caCert)
			}
		}
	}
	return rootCAs
}

func (r *Roots) UnmarshalJSON(data []byte) error {
	var roots []Root
	if err := json.Unmarshal(data, &roots); err != nil {
		return err
	}

	r.ByCommonName = make(map[string]Root)
	for _, root := range roots {
		r.ByCommonName[root.CommonName] = root
	}

	return nil
}

//go:embed roots-test.json
var dataRootsTest []byte

//go:embed roots-ref.json
var dataRootsRef []byte

//go:embed roots-prod.json
var dataRootsProd []byte

var RootsRef Roots

func init() {
	err := json.Unmarshal(dataRootsRef, &RootsRef)
	if err != nil {
		panic(err)
	}
}
