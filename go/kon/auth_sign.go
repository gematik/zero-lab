package kon

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httputil"

	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/authsignatureservice741"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/connectorcontext20"
)

// SignatureType values accepted by ExternalAuthenticate (TI signature schemes).
const (
	// SignatureTypeRSA selects PKCS#1 v1.5 with SHA-256 over the supplied hash.
	SignatureTypeRSA = "urn:ietf:rfc:3447"
	// SignatureTypeECDSA selects ECDSA with the card's domain parameters.
	SignatureTypeECDSA = "urn:bsi:tr:03111:ecdsa"
)

// The generated dss10core.Base64Data type encodes its character content as a
// child element <chardata>...</chardata> (the `xml:"chardata"` tag is missing
// the leading comma that would make it text content). The Konnektor rejects
// that as schema-nonconformant. We sidestep it by defining our own correctly
// tagged request/response shapes here. Once the generator is fixed we can
// switch back to the generated types.

type externalAuthenticateRequest struct {
	XMLName xml.Name                `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    externalAuthRequestBody `xml:"Body"`
}

type externalAuthRequestBody struct {
	XMLName xml.Name                   `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Outer   externalAuthRequestPayload `xml:"http://ws.gematik.de/conn/SignatureService/v7.4 ExternalAuthenticate"`
}

type externalAuthRequestPayload struct {
	CardHandle     string                     `xml:"http://ws.gematik.de/conn/ConnectorCommon/v5.0 CardHandle"`
	Context        connectorcontext20.Context `xml:"http://ws.gematik.de/conn/ConnectorContext/v2.0 Context"`
	OptionalInputs externalAuthOptionalInputs `xml:"http://ws.gematik.de/conn/SignatureService/v7.4 OptionalInputs"`
	BinaryString   externalAuthBinaryString   `xml:"http://ws.gematik.de/conn/SignatureService/v7.4 BinaryString"`
}

type externalAuthOptionalInputs struct {
	SignatureType string `xml:"urn:oasis:names:tc:dss:1.0:core:schema SignatureType"`
}

type externalAuthBinaryString struct {
	Base64Data base64DataElem `xml:"urn:oasis:names:tc:dss:1.0:core:schema Base64Data"`
}

type base64DataElem struct {
	MimeType string `xml:"MimeType,attr,omitempty"`
	Value    string `xml:",chardata"`
}

type externalAuthenticateResponseEnv struct {
	XMLName xml.Name                 `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    externalAuthResponseBody `xml:"Body"`
}

type externalAuthResponseBody struct {
	XMLName  xml.Name                   `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Response *externalAuthResponseInner `xml:"ExternalAuthenticateResponse"`
	Fault    *soapFault                 `xml:"Fault"`
}

type externalAuthResponseInner struct {
	SignatureObject *struct {
		Base64Signature *base64DataElem `xml:"Base64Signature"`
	} `xml:"SignatureObject"`
}

type soapFault struct {
	Code   string `xml:"faultcode"`
	String string `xml:"faultstring"`
}

// ExternalAuthenticate signs a hash with the card's authentication key (C.AUT)
// via the Konnektor's SignatureService.ExternalAuthenticate SOAP operation.
//
// The hash must be the digest the caller wants signed (the Konnektor does NOT
// hash it again). signatureType selects the algorithm: SignatureTypeECDSA for
// ECC SMC-B (the common case) or SignatureTypeRSA for legacy RSA cards.
//
// Returns the raw signature bytes. For ECDSA over brainpool, this is the BSI
// TR-03111 format: R||S, each padded to the curve byte length.
func (c *Client) ExternalAuthenticate(ctx context.Context, cardHandle string, hash []byte, signatureType string) ([]byte, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameAuthSignatureService)
	if err != nil {
		return nil, err
	}

	req := externalAuthenticateRequest{
		Body: externalAuthRequestBody{
			Outer: externalAuthRequestPayload{
				CardHandle: cardHandle,
				Context:    c.connectorContext(),
				OptionalInputs: externalAuthOptionalInputs{
					SignatureType: signatureType,
				},
				BinaryString: externalAuthBinaryString{
					Base64Data: base64DataElem{
						MimeType: "application/octet-stream",
						Value:    base64.StdEncoding.EncodeToString(hash),
					},
				},
			},
		},
	}

	body, err := xml.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("marshaling ExternalAuthenticate envelope: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, proxy.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating ExternalAuthenticate request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
	httpReq.Header.Set("SOAPAction", authsignatureservice741.OperationExternalAuthenticate.SOAPAction())

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		dump, _ := httputil.DumpRequestOut(httpReq, true)
		slog.Debug("SOAP request\n" + string(dump))
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("performing ExternalAuthenticate request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading ExternalAuthenticate response: %w", err)
	}

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		dump, _ := httputil.DumpResponse(resp, false)
		slog.Debug("SOAP response\n" + string(dump) + string(respBody))
	}

	var parsed externalAuthenticateResponseEnv
	if err := xml.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding ExternalAuthenticate response: %w", err)
	}

	if parsed.Body.Fault != nil {
		return nil, fmt.Errorf("ExternalAuthenticate SOAP fault: %s", parsed.Body.Fault.String)
	}
	if parsed.Body.Response == nil || parsed.Body.Response.SignatureObject == nil || parsed.Body.Response.SignatureObject.Base64Signature == nil {
		return nil, fmt.Errorf("ExternalAuthenticate: no Base64Signature in response")
	}
	raw, err := base64.StdEncoding.DecodeString(parsed.Body.Response.SignatureObject.Base64Signature.Value)
	if err != nil {
		return nil, fmt.Errorf("ExternalAuthenticate: decoding Base64Signature: %w", err)
	}
	if signatureType == SignatureTypeECDSA {
		// Some Konnektoren return ASN.1 DER even though TR-03111 mandates raw
		// R||S. Detect DER (leading 0x30 SEQUENCE) and convert; pass raw through
		// untouched so we play nice with both implementations.
		if normalized, ok := derECDSAToRaw(raw); ok {
			return normalized, nil
		}
	}
	return raw, nil
}

// derECDSAToRaw converts an ASN.1 DER-encoded ECDSA signature to the raw R||S
// form expected by JWS / brainpool consumers. Returns false if the input isn't
// recognizable DER, in which case the caller should pass the bytes through.
func derECDSAToRaw(der []byte) ([]byte, bool) {
	if len(der) < 8 || der[0] != 0x30 {
		return nil, false
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, false
	}
	if sig.R == nil || sig.S == nil {
		return nil, false
	}
	// Pad each component to the byte length of the larger of the two; that
	// matches the curve byte size in practice (R and S can't exceed it).
	size := (sig.R.BitLen() + 7) / 8
	if s := (sig.S.BitLen() + 7) / 8; s > size {
		size = s
	}
	// Round up to a common ECDSA curve byte size (32, 48, 66 — covers P-256/
	// brainpoolP256/P-384/P-521). Without this, a leading-zero R on a 256-bit
	// curve would shorten the output and break verifiers expecting fixed-width.
	switch {
	case size <= 32:
		size = 32
	case size <= 48:
		size = 48
	case size <= 66:
		size = 66
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, true
}
