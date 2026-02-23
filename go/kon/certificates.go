package kon

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
)

type CardCertificate struct {
	CertRef     string                          `json:"certRef"`
	Crypt       certificateservice601.CryptType `json:"crypt"`
	X509        *x509.Certificate               `json:"-"`
	IssuerName  string                          `json:"issuerName"`
	SubjectName string                          `json:"subjectName"`
	Admission   *gempki.AdmissionStatement      `json:"admission,omitempty"`
}

func (c *Client) ReadCardCertificates(ctx context.Context, cardHandle string, crypt certificateservice601.CryptType, certRefs ...certificateservicecommon20.CertRefEnum) ([]*CardCertificate, error) {
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
			Crypt:       crypt,
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

	var certs []*CardCertificate
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
		cc := &CardCertificate{
			CertRef:     string(info.CertRef),
			Crypt:       crypt,
			X509:        cert,
			IssuerName:  info.X509Data.X509IssuerSerial.X509IssuerName,
			SubjectName: info.X509Data.X509SubjectName,
		}
		if adm, err := gempki.ParseAdmissionStatement(cert); err == nil {
			cc.Admission = adm
		}
		certs = append(certs, cc)
	}

	return certs, nil
}

func (c *Client) ReadAllCardCertificates(ctx context.Context, card *Card) ([]*CardCertificate, error) {
	certRefs, err := CertRefsForCardType(card.CardType)
	if err != nil {
		return nil, fmt.Errorf("getting certificate refs: %w", err)
	}
	eccCerts, err := c.ReadCardCertificates(ctx, card.CardHandle, certificateservice601.CryptTypeEcc, certRefs...)
	if err != nil {
		return nil, fmt.Errorf("reading ECC certificates: %w", err)
	}
	rsaCerts, err := c.ReadCardCertificates(ctx, card.CardHandle, certificateservice601.CryptTypeRsa, certRefs...)
	if err != nil {
		slog.Warn("reading RSA certificates failed, maybe no RSA certificates on card", "error", err)
	} else {
	}

	return append(eccCerts, rsaCerts...), nil
}

func (c *Client) CheckCertificateExpiration(ctx context.Context, crypt certificateservice601.CryptType, cardHandle string) ([]certificateservice601.CertificateExpirationType, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameCertificateService)
	if err != nil {
		return nil, err
	}

	envelope := &certificateservice601.CheckCertificateExpirationEnvelope{
		CheckCertificateExpiration: &certificateservice601.CheckCertificateExpiration{
			CardHandle: cardHandle,
			Context:    c.connectorContext(),
			Crypt:      crypt,
		},
	}

	var resp certificateservice601.CheckCertificateExpirationResponseEnvelope
	if err := proxy.Call(ctx, &certificateservice601.OperationCheckCertificateExpiration, envelope, &resp); err != nil {
		return nil, fmt.Errorf("CheckCertificateExpiration: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("CheckCertificateExpiration SOAP fault: %s", resp.Fault.String)
	}
	if resp.CheckCertificateExpirationResponse == nil {
		return nil, fmt.Errorf("CheckCertificateExpiration: empty response")
	}

	return resp.CheckCertificateExpirationResponse.CertificateExpiration, nil
}
