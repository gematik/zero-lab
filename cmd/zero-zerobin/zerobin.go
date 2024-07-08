package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"html/template"
	"io"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/pkg"
	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/labstack/echo/v4"
)

var (
	//go:embed *.html
	templatesFS   embed.FS
	templateIndex *template.Template
)

func init() {
	templateIndex = template.Must(template.ParseFS(templatesFS, "index.html"))
}

func requestDetails(ctx echo.Context) map[string]interface{} {
	details := make(map[string]interface{})
	details["metadata"] = map[string]interface{}{
		"version": pkg.Version,
	}

	r := ctx.Request()

	details["method"] = r.Method
	details["proto"] = r.Proto
	details["remoteAddr"] = r.RemoteAddr
	details["host"] = r.Host
	details["requestURI"] = r.RequestURI
	details["headers"] = make(map[string]interface{})
	if ctx.Request().TLS != nil {
		details["tlsVersion"] = tls.VersionName(r.TLS.Version)
		details["tlsCipherSuite"] = tls.CipherSuiteName(r.TLS.CipherSuite)
		details["tlsHostname"] = r.TLS.ServerName
	}

	for k, v := range r.Header {
		details["headers"].(map[string]interface{})[k] = v
	}

	if r.TLS != nil && r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		details["tlsClientCertificates"] = make([]map[string]string, len(r.TLS.PeerCertificates))
		for i, cert := range r.TLS.PeerCertificates {
			details["tlsClientCertificates"].([]map[string]string)[i] = map[string]string{
				"subject":   cert.Subject.String(),
				"issuer":    cert.Issuer.String(),
				"notBefore": cert.NotBefore.String(),
				"notAfter":  cert.NotAfter.String(),
			}
		}
	}

	return details
}

func getEcho(ctx echo.Context) error {
	return ctx.JSONPretty(http.StatusOK, requestDetails(ctx), "  ")
}

// openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout example.key -out example.csr -subj "/CN=Zero Trust Client"
func issueCert(ctx echo.Context) error {

	var err error
	var csrDer []byte

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		slog.Error("error reading request body", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "error reading request body")
	}

	if ctx.Request().Header.Get("Content-Type") == "application/pkcs10" {
		csrDer = body
	} else {
		csrPEMBytes := body
		csrPEM, _ := pem.Decode(csrPEMBytes)
		if csrPEM == nil {
			slog.Error("error decoding PEM", "error", err)
			return echo.NewHTTPError(http.StatusBadRequest, "error decoding PEM")
		}
		csrDer = csrPEM.Bytes
	}

	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	subject := pkix.Name{
		CommonName: "Unattested Client",
	}
	cert, err := unregisteredClientsCA.SignCertificateRequest(csr, subject)
	if err != nil {
		slog.Error("error signing certificate", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error signing certificate")
	}

	certPEM, err := ca.EncodeCertToPEM(cert)
	if err != nil {
		slog.Error("error encoding certificate", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error encoding certificate")
	}

	ctx.Response().Header().Set("Content-Disposition", "attachment; filename=cert.pem")
	ctx.Blob(http.StatusOK, "application/x-pem-file", []byte(certPEM))

	return nil
}

func getIndex(ctx echo.Context) error {
	fqdn := util.GetEnv("FQDN", "localhost")

	return templateIndex.Execute(ctx.Response().Writer, map[string]interface{}{
		"fqdn": fqdn,
	})
}

func getUnattestedClientsCAChain(ctx echo.Context) error {
	ctx.Response().Header().Set("Content-Disposition", "attachment; filename=ca-chain.pem")
	return pem.Encode(ctx.Response(), &pem.Block{Type: "CERTIFICATE", Bytes: unregisteredClientsCA.IssuerCertificate().Raw})
}
