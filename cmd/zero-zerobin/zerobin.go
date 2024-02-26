package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func getEcho(ctx echo.Context) error {
	data := make(map[string]interface{})
	data["metadata"] = map[string]interface{}{
		"version": pkg.Version,
	}

	r := ctx.Request()

	data["method"] = r.Method
	data["proto"] = r.Proto
	data["remoteAddr"] = r.RemoteAddr
	data["host"] = r.Host
	data["requestURI"] = r.RequestURI
	data["headers"] = make(map[string]interface{})
	if ctx.Request().TLS != nil {
		data["tlsVersion"] = tls.VersionName(r.TLS.Version)
		data["tlsCipherSuite"] = tls.CipherSuiteName(r.TLS.CipherSuite)
		data["tlsHostname"] = r.TLS.ServerName
	}

	for k, v := range r.Header {
		data["headers"].(map[string]interface{})[k] = v
	}

	if r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		data["tlsClientCertificates"] = make([]map[string]string, len(r.TLS.PeerCertificates))
		for i, cert := range r.TLS.PeerCertificates {
			data["tlsClientCertificates"].([]map[string]string)[i] = map[string]string{
				"subject":   cert.Subject.String(),
				"issuer":    cert.Issuer.String(),
				"notBefore": cert.NotBefore.String(),
				"notAfter":  cert.NotAfter.String(),
			}
		}
	}

	return ctx.JSONPretty(http.StatusOK, data, "  ")
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
		if err != nil {
			slog.Error("error reading request body", "error", err)
			return echo.NewHTTPError(http.StatusBadRequest, "error reading request body")
		}
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
	cert, err := unattestedClientsCA.SignCertificateRequest(csr, subject)
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

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func getIndex(ctx echo.Context) error {
	fqdn := util.GetEnv("FQDN", "localhost")
	return ctx.Render(http.StatusOK, "zerobin-index.html", map[string]string{
		"fqdn": fqdn,
	})
}

func getUnattestedClientsCAChain(ctx echo.Context) error {
	ctx.Response().Header().Set("Content-Disposition", "attachment; filename=ca-chain.pem")
	return pem.Encode(ctx.Response(), &pem.Block{Type: "CERTIFICATE", Bytes: unattestedClientsCA.IssuerCertificate().Raw})
}
