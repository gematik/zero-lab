package kon

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
)

type AdmissionInfo struct {
	ProfessionItems    []string `json:"professionItems,omitempty"`
	ProfessionOids     []string `json:"professionOids,omitempty"`
	RegistrationNumber string   `json:"registrationNumber,omitempty"`
}

type CardCertificate struct {
	CertRef     string            `json:"certRef"`
	X509        *x509.Certificate `json:"-"`
	IssuerName  string            `json:"issuerName"`
	SubjectName string            `json:"subjectName"`
	Admission   *AdmissionInfo    `json:"admission,omitempty"`
}

func (c *Client) ReadCardCertificates(ctx context.Context, cardHandle string, certRefs ...certificateservicecommon20.CertRefEnum) ([]CardCertificate, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameCertificateService)
	if err != nil {
		return nil, err
	}

	refs := make([]string, len(certRefs))
	for i, r := range certRefs {
		refs[i] = string(r)
	}

	envelope := &certificateservice601.ReadCardCertificateEnvelope{
		ReadCardCertificate: &certificateservice601.ReadCardCertificate{
			CardHandle:  cardHandle,
			Context:     c.connectorContext(),
			CertRefList: certificateservice601.ReadCardCertificateCertRefList{CertRef: refs},
			Crypt:       "ECC",
		},
	}

	var resp certificateservice601.ReadCardCertificateResponseEnvelope
	if err := proxy.Call(ctx, &certificateservice601.OperationReadCardCertificate, envelope, &resp); err != nil {
		return nil, fmt.Errorf("ReadCardCertificate: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("ReadCardCertificate SOAP fault: %s", resp.Fault.String)
	}
	if resp.ReadCardCertificateResponse == nil {
		return nil, fmt.Errorf("ReadCardCertificate: empty response")
	}

	var certs []CardCertificate
	for _, info := range resp.ReadCardCertificateResponse.X509DataInfoList.X509DataInfo {
		if info.X509Data == nil || info.X509Data.X509Certificate == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(info.X509Data.X509Certificate)
		if err != nil {
			return nil, fmt.Errorf("decoding certificate %s: %w", info.CertRef, err)
		}
		cert, err := brainpool.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %s: %w", info.CertRef, err)
		}
		cc := CardCertificate{
			CertRef:     string(info.CertRef),
			X509:        cert,
			IssuerName:  info.X509Data.X509IssuerSerial.X509IssuerName,
			SubjectName: info.X509Data.X509SubjectName,
		}
		if adm, err := gempki.ParseAdmissionStatement(cert); err == nil {
			cc.Admission = &AdmissionInfo{
				ProfessionItems:    adm.ProfessionItems,
				ProfessionOids:     adm.ProfessionOids,
				RegistrationNumber: adm.RegistrationNumber,
			}
		}
		certs = append(certs, cc)
	}

	return certs, nil
}

func (c *Client) ReadAllCardCertificates(ctx context.Context, cardHandle string) ([]CardCertificate, error) {
	return c.ReadCardCertificates(ctx, cardHandle, "C.AUT")
}
