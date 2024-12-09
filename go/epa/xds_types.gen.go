package epa

import (
	"encoding/xml"
)

type AdhocQuery struct {
	XMLName            xml.Name             `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 AdhocQuery"`
	Id                 string               `xml:"id,attr"`
	Home               string               `xml:"home,attr"`
	Lid                string               `xml:"lid,attr"`
	ObjectType         string               `xml:"objectType,attr"`
	Status             string               `xml:"status,attr"`
	Slot               []Slot               `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot,omitempty"`
	Name               Name                 `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Name,omitempty"`
	Description        Description          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Description,omitempty"`
	VersionInfo        VersionInfo          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 VersionInfo,omitempty"`
	Classification     []Classification     `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Classification,omitempty"`
	ExternalIdentifier []ExternalIdentifier `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ExternalIdentifier,omitempty"`
	QueryExpression    QueryExpression      `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 QueryExpression,omitempty"`
}

type AdhocQueryRequest struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0 AdhocQueryRequest"`
	Id              string          `xml:"id,attr"`
	Comment         string          `xml:"comment,attr"`
	Federated       bool            `xml:"federated,attr"`
	Federation      string          `xml:"federation,attr"`
	StartIndex      int             `xml:"startIndex,attr"`
	MaxResults      int             `xml:"maxResults,attr"`
	RequestSlotList RequestSlotList `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RequestSlotList,omitempty"`
	ResponseOption  ResponseOption  `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0 ResponseOption"`
	AdhocQuery      AdhocQuery      `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 AdhocQuery"`
}

type AdhocQueryResponse struct {
	XMLName            xml.Name           `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0 AdhocQueryResponse"`
	Status             string             `xml:"status,attr"`
	RequestId          string             `xml:"requestId,attr"`
	StartIndex         int                `xml:"startIndex,attr"`
	TotalResultCount   int                `xml:"totalResultCount,attr"`
	ResponseSlotList   ResponseSlotList   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 ResponseSlotList,omitempty"`
	RegistryErrorList  RegistryErrorList  `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryErrorList,omitempty"`
	RegistryObjectList RegistryObjectList `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 RegistryObjectList"`
}

type Classification struct {
	XMLName              xml.Name             `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Classification"`
	Lid                  string               `xml:"lid,attr"`
	ObjectType           string               `xml:"objectType,attr"`
	Status               string               `xml:"status,attr"`
	ClassificationScheme string               `xml:"classificationScheme,attr"`
	ClassifiedObject     string               `xml:"classifiedObject,attr"`
	ClassificationNode   string               `xml:"classificationNode,attr"`
	NodeRepresentation   string               `xml:"nodeRepresentation,attr"`
	Name                 Name                 `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Name,omitempty"`
	Description          Description          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Description,omitempty"`
	VersionInfo          VersionInfo          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 VersionInfo,omitempty"`
	Classification       []Classification     `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Classification,omitempty"`
	ExternalIdentifier   []ExternalIdentifier `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ExternalIdentifier,omitempty"`
}

type Description struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Description"`
	LocalizedString LocalizedString `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 LocalizedString"`
}

type Document struct {
	XMLName xml.Name `xml:"urn:ihe:iti:xds-b:2007 Document"`
	Id      string   `xml:"id,attr"`
	Value   string   `xml:",chardata"`
}

type DocumentRequest struct {
	XMLName            xml.Name `xml:"urn:ihe:iti:xds-b:2007 DocumentRequest"`
	HomeCommunityId    string   `xml:"urn:ihe:iti:xds-b:2007 HomeCommunityId,omitempty"`
	RepositoryUniqueId string   `xml:"urn:ihe:iti:xds-b:2007 RepositoryUniqueId"`
	DocumentUniqueId   string   `xml:"urn:ihe:iti:xds-b:2007 DocumentUniqueId"`
}

type DocumentResponse struct {
	XMLName               xml.Name `xml:"urn:ihe:iti:xds-b:2007 DocumentResponse"`
	HomeCommunityId       string   `xml:"urn:ihe:iti:xds-b:2007 HomeCommunityId,omitempty"`
	RepositoryUniqueId    string   `xml:"urn:ihe:iti:xds-b:2007 RepositoryUniqueId"`
	DocumentUniqueId      string   `xml:"urn:ihe:iti:xds-b:2007 DocumentUniqueId"`
	NewRepositoryUniqueId string   `xml:"urn:ihe:iti:xds-b:2007 NewRepositoryUniqueId,omitempty"`
	NewDocumentUniqueId   string   `xml:"urn:ihe:iti:xds-b:2007 NewDocumentUniqueId,omitempty"`
	MimeType              string   `xml:"urn:ihe:iti:xds-b:2007 mimeType"`
	Document              string   `xml:"urn:ihe:iti:xds-b:2007 Document"`
}

type ExternalIdentifier struct {
	XMLName              xml.Name             `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ExternalIdentifier"`
	Lid                  string               `xml:"lid,attr"`
	ObjectType           string               `xml:"objectType,attr"`
	Status               string               `xml:"status,attr"`
	RegistryObject       string               `xml:"registryObject,attr"`
	IdentificationScheme string               `xml:"identificationScheme,attr"`
	Value                string               `xml:"value,attr"`
	Name                 Name                 `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Name,omitempty"`
	Description          Description          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Description,omitempty"`
	VersionInfo          VersionInfo          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 VersionInfo,omitempty"`
	Classification       []Classification     `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Classification,omitempty"`
	ExternalIdentifier   []ExternalIdentifier `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ExternalIdentifier,omitempty"`
}

type Identifiable struct {
	//XMLName xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Identifiable"`
	Id   string `xml:"id,attr"`
	Home string `xml:"home,attr"`
	Slot []Slot `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot,omitempty"`
}

type LocalizedString struct {
	XMLName xml.Name    `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 LocalizedString"`
	Lang    string      `xml:"lang,attr"`
	Charset interface{} `xml:"charset,attr"`
	Value   string      `xml:"value,attr"`
}

type Name struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Name"`
	LocalizedString LocalizedString `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 LocalizedString"`
}

type ObjectRef struct {
	XMLName       xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ObjectRef"`
	Id            string   `xml:"id,attr"`
	Home          string   `xml:"home,attr"`
	CreateReplica bool     `xml:"createReplica,attr"`
	Slot          []Slot   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot,omitempty"`
}

type ObjectRefList struct {
	XMLName   xml.Name  `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ObjectRefList"`
	ObjectRef ObjectRef `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ObjectRef"`
}

type ProvideAndRegisterDocumentSetRequest struct {
	XMLName              xml.Name             `xml:"urn:ihe:iti:xds-b:2007 ProvideAndRegisterDocumentSetRequest"`
	SubmitObjectsRequest SubmitObjectsRequest `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:lcm:3.0 SubmitObjectsRequest"`
	Document             []Document           `xml:"urn:ihe:iti:xds-b:2007 Document"`
}

type QueryExpression struct {
	XMLName       xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 QueryExpression"`
	QueryLanguage string   `xml:"queryLanguage,attr"`
}

type RegistryError struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryError"`
	CodeContext string   `xml:"codeContext,attr"`
	ErrorCode   string   `xml:"errorCode,attr"`
	Severity    string   `xml:"severity,attr"`
	Location    string   `xml:"location,attr"`
	Value       string   `xml:",chardata"`
}

type RegistryErrorList struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryErrorList"`
	HighestSeverity string          `xml:"highestSeverity,attr"`
	RegistryError   []RegistryError `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryError"`
}

type RegistryObjectList struct {
	XMLName xml.Name      `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 RegistryObjectList"`
	Items   []interface{} `xml:",any,omitempty"`
}

type RegistryResponse struct {
	XMLName           xml.Name          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryResponse"`
	Status            string            `xml:"status,attr"`
	RequestId         string            `xml:"requestId,attr"`
	ResponseSlotList  ResponseSlotList  `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 ResponseSlotList,omitempty"`
	RegistryErrorList RegistryErrorList `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryErrorList,omitempty"`
}

type RemoveObjectsRequest struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:lcm:3.0 RemoveObjectsRequest"`
	Id              string          `xml:"id,attr"`
	Comment         string          `xml:"comment,attr"`
	DeletionScope   string          `xml:"deletionScope,attr"`
	RequestSlotList RequestSlotList `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RequestSlotList,omitempty"`
	AdhocQuery      AdhocQuery      `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 AdhocQuery,omitempty"`
	ObjectRefList   ObjectRefList   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ObjectRefList,omitempty"`
}

type RequestSlotList struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RequestSlotList"`
	Slot    []Slot   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot,omitempty"`
}

type ResponseOption struct {
	XMLName               xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0 ResponseOption"`
	ReturnType            string   `xml:"returnType,attr"`
	ReturnComposedObjects bool     `xml:"returnComposedObjects,attr"`
}

type ResponseSlotList struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 ResponseSlotList"`
	Slot    []Slot   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot,omitempty"`
}

type RetrieveDocumentSetRequest struct {
	XMLName         xml.Name          `xml:"urn:ihe:iti:xds-b:2007 RetrieveDocumentSetRequest"`
	DocumentRequest []DocumentRequest `xml:"urn:ihe:iti:xds-b:2007 DocumentRequest"`
}

type RetrieveDocumentSetResponse struct {
	XMLName          xml.Name           `xml:"urn:ihe:iti:xds-b:2007 RetrieveDocumentSetResponse"`
	RegistryResponse RegistryResponse   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RegistryResponse"`
	DocumentResponse []DocumentResponse `xml:"urn:ihe:iti:xds-b:2007 DocumentResponse"`
}

type Slot struct {
	XMLName   xml.Name  `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot"`
	Name      string    `xml:"name,attr"`
	SlotType  string    `xml:"slotType,attr"`
	ValueList ValueList `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ValueList"`
}

type SubmitObjectsRequest struct {
	XMLName            xml.Name           `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:lcm:3.0 SubmitObjectsRequest"`
	Id                 string             `xml:"id,attr"`
	Comment            string             `xml:"comment,attr"`
	RequestSlotList    RequestSlotList    `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0 RequestSlotList,omitempty"`
	RegistryObjectList RegistryObjectList `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 RegistryObjectList,omitempty"`
}

type ValueList struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ValueList"`
	Value   string   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Value"`
}

type VersionInfo struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 VersionInfo"`
	VersionName string   `xml:"versionName,attr"`
	Comment     string   `xml:"comment,attr"`
}

type RegistryPackage struct {
	XMLName            xml.Name             `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 RegistryPackage"`
	Id                 string               `xml:"id,attr"`
	Home               string               `xml:"home,attr"`
	Lid                string               `xml:"lid,attr"`
	ObjectType         string               `xml:"objectType,attr"`
	Status             string               `xml:"status,attr"`
	Slot               []Slot               `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Slot,omitempty"`
	Name               Name                 `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Name,omitempty"`
	Description        Description          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Description,omitempty"`
	VersionInfo        VersionInfo          `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 VersionInfo,omitempty"`
	Classification     []Classification     `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 Classification,omitempty"`
	ExternalIdentifier []ExternalIdentifier `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 ExternalIdentifier,omitempty"`
	RegistryObjectList RegistryObjectList   `xml:"urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0 RegistryObjectList,omitempty"`
}
