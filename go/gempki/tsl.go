package gempki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

const URLTrustServiceListTest = "https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml"
const URLTrustServiceListRef = "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml"
const URLTrustServiceListProd = "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml"

func IsTSLUpdateAvailable(ctx context.Context, httpClient *http.Client, url string, hash string) (bool, error) {
	// construct sha2 url
	sha2Url := strings.Replace(url, ".xml", ".sha2", 1)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sha2Url, nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP response error: %s", resp.Status)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// compare hash
	newHash := strings.TrimSpace(string(body))

	if hash == newHash {
		slog.Debug("TSL is up to date", "url", url)
		return false, nil
	}

	return true, nil
}

func UpdateTSL(ctx context.Context, httpClient *http.Client, tsl *TrustServiceStatusList) (*TrustServiceStatusList, error) {

	updateAvailable, err := IsTSLUpdateAvailable(ctx, httpClient, tsl.Url, tsl.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to check for TSL update: %w", err)
	} else if !updateAvailable {
		slog.Debug("No TSL update available", "url", tsl.Url)
		return tsl, nil
	}

	slog.Info("TSL update available", "url", tsl.Url)
	return LoadTSL(ctx, httpClient, tsl.Url)
}

func LoadTSL(ctx context.Context, httpClient *http.Client, url string) (*TrustServiceStatusList, error) {
	slog.Info("Loading TSL", "url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP response error: %s", resp.Status)
	}
	defer resp.Body.Close()

	return ParseTSL(resp.Body, url)
}

func ParseTSL(input io.Reader, url string) (*TrustServiceStatusList, error) {
	body, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	tsl := new(TrustServiceStatusList)
	err = xml.Unmarshal(body, tsl)
	if err != nil {
		return nil, err
	}
	tsl.Hash = hashStr
	tsl.Url = url
	tsl.Raw = body
	return tsl, nil
}

type DateTime time.Time

func (t *DateTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v string
	d.DecodeElement(&v, &start)
	parse, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return err
	}
	*t = DateTime(parse)
	return nil
}

func (t *DateTime) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	v := time.Time(*t).Format(time.RFC3339)
	e.EncodeElement(v, start)
	return nil
}

func (t *DateTime) UnmarshalJSON(data []byte) error {
	str := string(data)
	parse, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err
	}
	*t = DateTime(parse)
	return nil
}

func (t *DateTime) MarshalJSON() ([]byte, error) {
	str := fmt.Sprintf("\"%s\"", time.Time(*t).Format(time.RFC3339))
	return []byte(str), nil
}

const (
	ServiceTypeCaPkc          = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
	ServiceTypeCaCvc          = "http://uri.telematik/TrstSvc/Svctype/CA/CVC"
	ServiceTypeCertstatusOcsp = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"
)

type MultiLangString struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}
type MultiLangStringList []MultiLangString
type InternationalNameList []MultiLangString

type MultiLangUri struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}
type MultiLangUriList []MultiLangUri

type PostalAddress struct {
	Lang            string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	StreetAddress   string `xml:"http://uri.etsi.org/02231/v2# StreetAddress"`
	Locality        string `xml:"http://uri.etsi.org/02231/v2# Locality"`
	StateOrProvince string `xml:"http://uri.etsi.org/02231/v2# StateOrProvince"`
	PostalCode      string `xml:"http://uri.etsi.org/02231/v2# PostalCode"`
	CountryName     string `xml:"http://uri.etsi.org/02231/v2# CountryName"`
}
type MultiLangPostalAddresses []PostalAddress

type ElectronicAddress MultiLangUriList

type SchemeOperatorAddress struct {
	PostalAddresses   MultiLangPostalAddresses `xml:"http://uri.etsi.org/02231/v2# PostalAddresses>PostalAddress"`
	ElectronicAddress ElectronicAddress        `xml:"http://uri.etsi.org/02231/v2# ElectronicAddress>URI"`
}

type PolicyOrLegalNotice struct {
	TSLLegalNotice MultiLangStringList `xml:"http://uri.etsi.org/02231/v2# TSLLegalNotice"`
	TSLPolicy      MultiLangStringList `xml:"http://uri.etsi.org/02231/v2# TSLPolicy"`
}

type AdditionalInformation struct {
	TextualInformation MultiLangStringList `xml:"http://uri.etsi.org/02231/v2# TextualInformation"`
}

type OtherTSLPointer struct {
	TSLLocation           []string              `xml:"http://uri.etsi.org/02231/v2# TSLLocation"`
	AdditionalInformation AdditionalInformation `xml:"http://uri.etsi.org/02231/v2# AdditionalInformation"`
}

type SchemeInformation struct {
	TSLVersionIdentifier        int64                 `xml:"http://uri.etsi.org/02231/v2# TSLVersionIdentifier"`
	TSLSequenceNumber           int64                 `xml:"http://uri.etsi.org/02231/v2# TSLSequenceNumber"`
	TSLType                     string                `xml:"http://uri.etsi.org/02231/v2# TSLType"`
	SchemeOperatorName          InternationalNameList `xml:"http://uri.etsi.org/02231/v2# SchemeOperatorName>Name"`
	SchemeOperatorAddress       SchemeOperatorAddress `xml:"http://uri.etsi.org/02231/v2# SchemeOperatorAddress"`
	SchemeName                  InternationalNameList `xml:"http://uri.etsi.org/02231/v2# SchemeName>Name"`
	SchemeInformationURI        MultiLangUriList      `xml:"http://uri.etsi.org/02231/v2# SchemeInformationURI>URI"`
	StatusDeterminationApproach string                `xml:"http://uri.etsi.org/02231/v2# StatusDeterminationApproach"`
	PolicyOrLegalNotice         PolicyOrLegalNotice   `xml:"http://uri.etsi.org/02231/v2# PolicyOrLegalNotice"`
	HistoricalInformationPeriod int64                 `xml:"http://uri.etsi.org/02231/v2# HistoricalInformationPeriod"`
	PointersToOtherTSL          []OtherTSLPointer     `xml:"http://uri.etsi.org/02231/v2# PointersToOtherTSL>OtherTSLPointer"`
	ListIssueDateTime           DateTime              `xml:"http://uri.etsi.org/02231/v2# ListIssueDateTime"`
	NextUpdate                  DateTime              `xml:"http://uri.etsi.org/02231/v2# NextUpdate>dateTime"`
}

type DigitalId struct {
	X509CertificateRaw []byte            `xml:"http://uri.etsi.org/02231/v2# X509Certificate"`
	X509Certificate    *x509.Certificate `xml:"-"`
	CVCertificateRaw   []byte            `xml:"http://uri.etsi.org/02231/v2# Other>CVCertificate"`
}

func (d *DigitalId) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	surrogate := struct {
		X509CertificateBase64 []byte `xml:"http://uri.etsi.org/02231/v2# X509Certificate"`
		CVCertificateBase64   []byte `xml:"http://uri.etsi.org/02231/v2# Other>CVCertificate"`
	}{}
	err := decoder.DecodeElement(&surrogate, &start)
	if err != nil {
		return err
	}
	if len(surrogate.X509CertificateBase64) > 0 {
		if d.X509CertificateRaw, err = base64.StdEncoding.DecodeString(string(surrogate.X509CertificateBase64)); err != nil {
			return fmt.Errorf("failed to decode base64: %w", err)
		}
		if d.X509Certificate, err = brainpool.ParseCertificate(d.X509CertificateRaw); err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
	}
	if len(surrogate.CVCertificateBase64) > 0 {
		if d.CVCertificateRaw, err = base64.StdEncoding.DecodeString(string(surrogate.CVCertificateBase64)); err != nil {
			return fmt.Errorf("failed to decode base64: %w", err)
		}
	}

	return nil
}

type ServiceDigitalIdentity struct {
	DigitalId DigitalId `xml:"http://uri.etsi.org/02231/v2# DigitalId"`
}

type AdditionalServiceInformation struct {
	URI              MultiLangUri `xml:"http://uri.etsi.org/02231/v2# URI"`
	InformationValue string       `xml:"http://uri.etsi.org/02231/v2# InformationValue"`
}

type Extension struct {
	Critical                     bool                           `xml:"Critical,attr"`
	ExtensionOID                 string                         `xml:"http://uri.etsi.org/02231/v2# ExtensionOID"`
	ExtensionValue               string                         `xml:"http://uri.etsi.org/02231/v2# ExtensionValue"`
	AdditionalServiceInformation []AdditionalServiceInformation `xml:"http://uri.etsi.org/02231/v2# AdditionalServiceInformation"`
}

type ServiceInformation struct {
	ServiceTypeIdentifier        string                 `xml:"http://uri.etsi.org/02231/v2# ServiceTypeIdentifier"`
	ServiceName                  InternationalNameList  `xml:"http://uri.etsi.org/02231/v2# ServiceName>Name"`
	ServiceDigitalIdentity       ServiceDigitalIdentity `xml:"http://uri.etsi.org/02231/v2# ServiceDigitalIdentity"`
	ServiceStatus                string                 `xml:"http://uri.etsi.org/02231/v2# ServiceStatus"`
	StatusStartingTime           DateTime               `xml:"http://uri.etsi.org/02231/v2# StatusStartingTime"`
	SchemeServiceDefinitionURI   MultiLangUriList       `xml:"http://uri.etsi.org/02231/v2# SchemeServiceDefinitionURI>URI"`
	ServiceSupplyPoints          []string               `xml:"http://uri.etsi.org/02231/v2# ServiceSupplyPoints>ServiceSupplyPoint"`
	ServiceInformationExtensions []Extension            `xml:"http://uri.etsi.org/02231/v2# ServiceInformationExtensions>Extension"`
}

type TSPService struct {
	ServiceInformation ServiceInformation `xml:"http://uri.etsi.org/02231/v2# ServiceInformation"`
}

type TSPAddress struct {
	PostalAddresses   MultiLangPostalAddresses `xml:"http://uri.etsi.org/02231/v2# PostalAddresses>PostalAddress"`
	ElectronicAddress ElectronicAddress        `xml:"http://uri.etsi.org/02231/v2# ElectronicAddress>URI"`
}

type TSPInformation struct {
	TSPName           InternationalNameList `xml:"http://uri.etsi.org/02231/v2# TSPName>Name"`
	TSPTradeName      InternationalNameList `xml:"http://uri.etsi.org/02231/v2# TSPTradeName>Name"`
	TSPInformationURI MultiLangUriList      `xml:"http://uri.etsi.org/02231/v2# TSPInformationURI>URI"`
	TSPAddress        TSPAddress            `xml:"http://uri.etsi.org/02231/v2# TSPAddress"`
}

type TrustServiceProvider struct {
	TSPInformation TSPInformation `xml:"http://uri.etsi.org/02231/v2# TSPInformation"`
	TSPServices    []TSPService   `xml:"http://uri.etsi.org/02231/v2# TSPServices>TSPService"`
}

type TrustServiceStatusList struct {
	Hash                     string                 `xml:"-"`
	Url                      string                 `xml:"-"`
	Raw                      []byte                 `xml:"-"`
	XMLName                  xml.Name               `xml:"http://uri.etsi.org/02231/v2# TrustServiceStatusList"`
	Id                       string                 `xml:"Id,attr"`
	TSLTag                   string                 `xml:"TSLTag,attr"`
	SchemeInformation        SchemeInformation      `xml:"http://uri.etsi.org/02231/v2# SchemeInformation"`
	TrustServiceProviderList []TrustServiceProvider `xml:"http://uri.etsi.org/02231/v2# TrustServiceProviderList>TrustServiceProvider"`
}
