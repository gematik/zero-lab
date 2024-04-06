package util

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func JWSToText(jwsData string) string {
	sb := strings.Builder{}
	parts := strings.Split(jwsData, ".")

	sb.WriteString("base64url(")
	sb.WriteString(tokenPartToText(parts[0]))
	sb.WriteString(").base64url(")
	sb.WriteString(tokenPartToText(parts[1]))
	sb.WriteString(").signature(")
	sb.WriteString(parts[2][0:10])
	sb.WriteString("...)\n")
	return sb.String()
}

func tokenPartToText(s string) string {
	dataBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err.Error()
	}
	dataMap := make(map[string]interface{})
	err = json.Unmarshal(dataBytes, &dataMap)
	if err != nil {
		return string(dataBytes)
	}

	jsonBytes, err := json.MarshalIndent(dataMap, "  ", "  ")
	if err != nil {
		return err.Error()
	}
	return string(jsonBytes)
}

func ResponseToText(resp *http.Response) string {
	sb := strings.Builder{}
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(resp.Status)
	sb.WriteString("\n")
	for k, v := range resp.Header {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(v, ", "))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		sb.WriteString(err.Error())
	} else {
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
		sb.WriteString(string(body))
	}
	return sb.String()
}

func CertificateToText(cert *x509.Certificate) string {
	if cert == nil {
		return "nil"
	}
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("subject: %s\n", cert.Subject.String()))
	sb.WriteString(fmt.Sprintf("issuer: %s\n", cert.Issuer.String()))
	sb.WriteString(fmt.Sprintf("publicKeyAlgorithm: %s\n", cert.PublicKeyAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("signatureAlgorithm: %s\n", cert.SignatureAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("serialNumber: %s\n", cert.SerialNumber.String()))
	sb.WriteString(fmt.Sprintf("notBefore: %s\n", cert.NotBefore.String()))
	sb.WriteString(fmt.Sprintf("notAfter: %s\n", cert.NotAfter.String()))
	return strings.Trim(sb.String(), " \n")

}
