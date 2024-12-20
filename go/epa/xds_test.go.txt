package epa_test

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
)

var errorResponse = `Content-Type: [multipart/related; type="application/xop+xml"; boundary="uuid:6646f5f3-3c94-4ad6-a97b-085c0c1365e1"; start="<root.message@cxf.apache.org>"; start-info="application/soap+xml"]
    xds_test.go:58: Response:
        --uuid:6646f5f3-3c94-4ad6-a97b-085c0c1365e1
        Content-Type: application/xop+xml; charset=UTF-8; type="application/soap+xml"
        Content-Transfer-Encoding: binary
        Content-ID: <root.message@cxf.apache.org>

        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><soap:Fault><soap:Code><soap:Value>soap:Receiver</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang="en">Schema validation failed</soap:Text></soap:Reason></soap:Fault></soap:Body></soap:Envelope>
        --uuid:6646f5f3-3c94-4ad6-a97b-085c0c1365e1--`

var findFoldersResponse = `<soap:Envelope
	xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header>
		<Action
			xmlns="http://www.w3.org/2005/08/addressing">urn:ihe:iti:2007:RegistryStoredQueryResponse
		</Action>
		<MessageID
			xmlns="http://www.w3.org/2005/08/addressing">urn:uuid:1c770fee-5786-4486-9d79-314bc1ae4e71
		</MessageID>
		<To
			xmlns="http://www.w3.org/2005/08/addressing">http://www.w3.org/2005/08/addressing/anonymous
		</To>
		<RelatesTo
			xmlns="http://www.w3.org/2005/08/addressing">urn:uuid:e41cd943-5c36-466e-bbce-afb455d6c75c
		</RelatesTo>
	</soap:Header>
	<soap:Body>
		<ns3:AdhocQueryResponse
			xmlns:ns2="urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0"
			xmlns:ns3="urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0"
			xmlns:ns4="urn:oasis:names:tc:ebxml-regrep:xsd:lcm:3.0"
			xmlns:ns5="urn:ihe:iti:xds-b:2007"
			xmlns:ns6="urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0"
			xmlns:ns7="urn:ihe:iti:rmd:2017" startIndex="0" totalResultCount="14" status="urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success">
			<ns6:RegistryObjectList>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:b878db05-49e4-4f74-a329-b3bcdd8082c4" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Befunde/Diagnosen/Berichte"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Befunde/Diagnosen/Berichte"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:b878db05-49e4-4f74-a329-b3bcdd8082c4" nodeRepresentation="reports" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:673044b2-5afe-49c4-bd16-876252efdce1">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.511</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Befunde/Diagnosen/Berichte"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:b878db05-49e4-4f74-a329-b3bcdd8082c4" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:8d10f9d5-41d2-46ad-8204-5a5a00e6ad6e"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:b878db05-49e4-4f74-a329-b3bcdd8082c4" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:8d10f9d5-41d2-46ad-8204-5a5a00e6ad6e">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:b878db05-49e4-4f74-a329-b3bcdd8082c4" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.1" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:8d10f9d5-41d2-46ad-8204-5a5a00e6ad6e">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:7c1054ea-a4df-4a1b-8e10-209f6d8812ee" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Elektronischer Medikationsplan"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Elektronischer Medikationsplan"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:7c1054ea-a4df-4a1b-8e10-209f6d8812ee" nodeRepresentation="emp" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:47756d5d-ec41-48f0-9f64-8661d3b34882">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Elektronischer Medikationsplan"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:7c1054ea-a4df-4a1b-8e10-209f6d8812ee" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:7ce835c9-abdc-4b35-bd2f-52c419c02798"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:7c1054ea-a4df-4a1b-8e10-209f6d8812ee" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:7ce835c9-abdc-4b35-bd2f-52c419c02798">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:7c1054ea-a4df-4a1b-8e10-209f6d8812ee" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.2" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:7ce835c9-abdc-4b35-bd2f-52c419c02798">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:a7bb6be7-d756-46dd-90d4-4020ed55b777" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Notfalldaten"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Notfalldaten"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:a7bb6be7-d756-46dd-90d4-4020ed55b777" nodeRepresentation="emergency" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:41c4d53a-f331-4ba1-9a6f-c2d87e0a9aa5">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Notfalldaten"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:a7bb6be7-d756-46dd-90d4-4020ed55b777" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:a00c2d26-91c2-4693-9091-77136db82a5c"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:a7bb6be7-d756-46dd-90d4-4020ed55b777" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:a00c2d26-91c2-4693-9091-77136db82a5c">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:a7bb6be7-d756-46dd-90d4-4020ed55b777" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.3" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:a00c2d26-91c2-4693-9091-77136db82a5c">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:2ed345b1-35a3-49e1-a4af-d71ca4f23e57" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="eArztbrief"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="eArztbrief"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:2ed345b1-35a3-49e1-a4af-d71ca4f23e57" nodeRepresentation="eab" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:4a6253da-85b5-42dc-af90-1e8da2132b7a">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="eArztbrief"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:2ed345b1-35a3-49e1-a4af-d71ca4f23e57" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:a165b13f-2af8-4bf9-9b4d-96fde03285a3"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:2ed345b1-35a3-49e1-a4af-d71ca4f23e57" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:a165b13f-2af8-4bf9-9b4d-96fde03285a3">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:2ed345b1-35a3-49e1-a4af-d71ca4f23e57" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.4" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:a165b13f-2af8-4bf9-9b4d-96fde03285a3">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:af547321-b8e8-4e1d-b9af-51bb4a990bda" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Zahnbonusheft"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Zahnbonusheft"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:af547321-b8e8-4e1d-b9af-51bb4a990bda" nodeRepresentation="dental" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:59a1cb6c-d3e9-4e1b-8f7f-8907f8409ba4">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Zahnbonusheft"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:af547321-b8e8-4e1d-b9af-51bb4a990bda" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:8c478262-a8ea-4b47-9c11-8a206efc1067"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:af547321-b8e8-4e1d-b9af-51bb4a990bda" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:8c478262-a8ea-4b47-9c11-8a206efc1067">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:af547321-b8e8-4e1d-b9af-51bb4a990bda" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.5" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:8c478262-a8ea-4b47-9c11-8a206efc1067">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:2c898452-4667-40e3-9d3e-c09d7385b527" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Kinderuntersuchungsheft"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Kinderuntersuchungsheft"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:2c898452-4667-40e3-9d3e-c09d7385b527" nodeRepresentation="child" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:86e59f6a-800e-4b5e-b56a-85ad58fb25f6">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Kinderuntersuchungsheft"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:2c898452-4667-40e3-9d3e-c09d7385b527" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:fa9e2446-7181-4ebf-9823-ded93b2d1be0"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:2c898452-4667-40e3-9d3e-c09d7385b527" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:fa9e2446-7181-4ebf-9823-ded93b2d1be0">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:2c898452-4667-40e3-9d3e-c09d7385b527" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.6" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:fa9e2446-7181-4ebf-9823-ded93b2d1be0">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:9c3edaf3-a978-46fe-8e6e-021ff4aca60b" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Impfpass"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Impfpass"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:9c3edaf3-a978-46fe-8e6e-021ff4aca60b" nodeRepresentation="vaccination" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:919cefb9-5c07-4c31-94d8-6f8fc72ef2e5">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Impfpass"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:9c3edaf3-a978-46fe-8e6e-021ff4aca60b" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:0f396bf8-e6f8-46d1-944c-a48d3eaa98ce"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:9c3edaf3-a978-46fe-8e6e-021ff4aca60b" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:0f396bf8-e6f8-46d1-944c-a48d3eaa98ce">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:9c3edaf3-a978-46fe-8e6e-021ff4aca60b" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.7" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:0f396bf8-e6f8-46d1-944c-a48d3eaa98ce">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:d236c9a2-ab01-4902-a00a-1e1dff439fe7" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="vom Versicherten eingestellte Dokumente"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="vom Versicherten eingestellte Dokumente"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:d236c9a2-ab01-4902-a00a-1e1dff439fe7" nodeRepresentation="patient" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:7896bf48-8ff9-46d6-a066-05c4a0d78501">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="vom Versicherten eingestellte Dokumente"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:d236c9a2-ab01-4902-a00a-1e1dff439fe7" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:086477d5-8f9d-4cea-b1fa-f9add3a9b3c7"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:d236c9a2-ab01-4902-a00a-1e1dff439fe7" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:086477d5-8f9d-4cea-b1fa-f9add3a9b3c7">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:d236c9a2-ab01-4902-a00a-1e1dff439fe7" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.8" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:086477d5-8f9d-4cea-b1fa-f9add3a9b3c7">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:91420e5e-e055-4c7d-b14e-96239e8f0d6d" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Quittungen"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Quittungen"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:91420e5e-e055-4c7d-b14e-96239e8f0d6d" nodeRepresentation="receipt" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:a4923e66-469e-484e-b44e-3f7ba6a21aa4">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Quittungen"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:91420e5e-e055-4c7d-b14e-96239e8f0d6d" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:e688f3a3-dffe-4904-b727-4a23ad607397"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:91420e5e-e055-4c7d-b14e-96239e8f0d6d" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:e688f3a3-dffe-4904-b727-4a23ad607397">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:91420e5e-e055-4c7d-b14e-96239e8f0d6d" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.9" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:e688f3a3-dffe-4904-b727-4a23ad607397">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:2d62bf9e-062a-4aa7-9951-9f33bbc665b5" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Pflegedokumente"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Pflegedokumente"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:2d62bf9e-062a-4aa7-9951-9f33bbc665b5" nodeRepresentation="care" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:bc964964-eb82-4317-b28a-68984d69786a">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Pflegedokumente"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:2d62bf9e-062a-4aa7-9951-9f33bbc665b5" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:a197b093-c090-406d-879b-ddfc774b9524"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:2d62bf9e-062a-4aa7-9951-9f33bbc665b5" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:a197b093-c090-406d-879b-ddfc774b9524">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:2d62bf9e-062a-4aa7-9951-9f33bbc665b5" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.10" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:a197b093-c090-406d-879b-ddfc774b9524">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:aa7d10d6-204a-47aa-be73-44bdcb77512f" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Elektronische Arbeitsunfähigkeitsbescheinigungen"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Elektronische Arbeitsunfähigkeitsbescheinigungen"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:aa7d10d6-204a-47aa-be73-44bdcb77512f" nodeRepresentation="eau" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:67aed73c-2f32-4df2-95c2-063408f1cd20">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Elektronische Arbeitsunfähigkeitsbescheinigungen"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:aa7d10d6-204a-47aa-be73-44bdcb77512f" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:7df1b885-8be6-4241-b78e-34bdcafc1f72"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:aa7d10d6-204a-47aa-be73-44bdcb77512f" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:7df1b885-8be6-4241-b78e-34bdcafc1f72">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:aa7d10d6-204a-47aa-be73-44bdcb77512f" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.11" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:7df1b885-8be6-4241-b78e-34bdcafc1f72">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:605a9f3c-bfe8-4830-a3e3-25a4ec6612cb" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="in andere Kategorien nicht einzuordnende Dokumente, eDMPs sowie Telemedizinisches Monitoring"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="in andere Kategorien nicht einzuordnende Dokumente, eDMPs sowie Telemedizinisches Monitoring"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:605a9f3c-bfe8-4830-a3e3-25a4ec6612cb" nodeRepresentation="other" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:fa71e272-e6e9-42b5-bcd1-7127a276e1fe">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="in andere Kategorien nicht einzuordnende Dokumente, eDMPs sowie Telemedizinisches Monitoring"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:605a9f3c-bfe8-4830-a3e3-25a4ec6612cb" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:0d90b806-5644-406e-ae9b-97b9325dae97"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:605a9f3c-bfe8-4830-a3e3-25a4ec6612cb" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:0d90b806-5644-406e-ae9b-97b9325dae97">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:605a9f3c-bfe8-4830-a3e3-25a4ec6612cb" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.12" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:0d90b806-5644-406e-ae9b-97b9325dae97">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:173f4204-fb93-4a1a-a1f6-316703b79539" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Heilbehandlung und Rehabilitation"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Heilbehandlung und Rehabilitation"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:173f4204-fb93-4a1a-a1f6-316703b79539" nodeRepresentation="rehab" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:2462c223-5414-44ec-966f-8a88e14deb61">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Heilbehandlung und Rehabilitation"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:173f4204-fb93-4a1a-a1f6-316703b79539" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:e8e4585d-860c-42c8-9f05-68f1755a0b18"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:173f4204-fb93-4a1a-a1f6-316703b79539" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:e8e4585d-860c-42c8-9f05-68f1755a0b18">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:173f4204-fb93-4a1a-a1f6-316703b79539" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.14" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:e8e4585d-860c-42c8-9f05-68f1755a0b18">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
				<ns6:RegistryPackage status="urn:oasis:names:tc:ebxml-regrep:StatusType:Approved" id="urn:uuid:6a8e383d-8705-4b0e-a140-39a5f144501d" home="urn:oid:1.2.276.0.76.3.1.466.2.1.4.90.1">
					<ns6:Slot name="lastUpdateTime">
						<ns6:ValueList>
							<ns6:Value>20241127182723</ns6:Value>
						</ns6:ValueList>
					</ns6:Slot>
					<ns6:Name>
						<ns6:LocalizedString value="Elektronische Abschriften von der Patientenakte"/>
					</ns6:Name>
					<ns6:Description>
						<ns6:LocalizedString value="Elektronische Abschriften von der Patientenakte"/>
					</ns6:Description>
					<ns6:Classification classificationScheme="urn:uuid:1ba97051-7806-41a8-a48b-8fce7af683c5" classifiedObject="urn:uuid:6a8e383d-8705-4b0e-a140-39a5f144501d" nodeRepresentation="transcripts" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:b101a5ef-e5b0-44d1-a84b-5984a1e8ba95">
						<ns6:Slot name="codingScheme">
							<ns6:ValueList>
								<ns6:Value>1.2.276.0.76.5.512</ns6:Value>
							</ns6:ValueList>
						</ns6:Slot>
						<ns6:Name>
							<ns6:LocalizedString value="Elektronische Abschriften von der Patientenakte"/>
						</ns6:Name>
					</ns6:Classification>
					<ns6:Classification classifiedObject="urn:uuid:6a8e383d-8705-4b0e-a140-39a5f144501d" classificationNode="urn:uuid:d9d542f3-6cc4-48b6-8870-ea235fbc94c2" objectType="urn:oasis:names:tc:ebXML-regrep:ObjectType:RegistryObject:Classification" id="urn:uuid:7b6bc590-1924-4ac4-a9fc-e1036810a5b9"/>
					<ns6:ExternalIdentifier registryObject="urn:uuid:6a8e383d-8705-4b0e-a140-39a5f144501d" identificationScheme="urn:uuid:f64ffdf0-4b97-4e06-b79f-a52b38ec2f8a" value="X110611629^^^&amp;1.2.276.0.76.4.8&amp;ISO" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:7b6bc590-1924-4ac4-a9fc-e1036810a5b9">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.patientId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
					<ns6:ExternalIdentifier registryObject="urn:uuid:6a8e383d-8705-4b0e-a140-39a5f144501d" identificationScheme="urn:uuid:75df8f67-9973-4fbe-a900-df66cefecc5a" value="1.3.6.1.4.1.36908.2002.83.15" objectType="urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier" id="urn:uuid:7b6bc590-1924-4ac4-a9fc-e1036810a5b9">
						<ns6:Name>
							<ns6:LocalizedString value="XDSFolder.uniqueId"/>
						</ns6:Name>
					</ns6:ExternalIdentifier>
				</ns6:RegistryPackage>
			</ns6:RegistryObjectList>
		</ns3:AdhocQueryResponse>
	</soap:Body>
</soap:Envelope>`

//go:embed templates/getFoldersAndContents.xml
var getFoldersAndContentsTmplStr string
var getFoldersAndContentsTmpl = template.Must(template.New("getFoldersAndContents.xml").Parse(getFoldersAndContentsTmplStr))

//go:embed templates/findFolders.xml
var findFoldersTmplStr string
var findFoldersTmpl = template.Must(template.New("findFolders.xml").Parse(findFoldersTmplStr))

func TestXDS(t *testing.T) {

	var body bytes.Buffer
	if err := findFoldersTmpl.Execute(&body, struct {
		InsurantID string
	}{
		InsurantID: "X110611629",
	}); err != nil {
		t.Fatalf("Error executing template: %v", err)
	}
	url := "http://localhost:8082/insurants/X110611629/vau/epa/xds-document/api/I_Document_Management_Insurant"
	req, _ := http.NewRequest("POST", url, &body)
	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Response status: %s", resp.Status)

	for name, value := range resp.Header {
		t.Logf("%s: %s", name, value)
	}

	/*
		envelope := new(epa.Envelope)
		if err := xml.NewDecoder(resp.Body).Decode(&envelope); err != nil {
			t.Fatalf("Error unmarshaling response: %v", err)
		}

		t.Logf("Envelope: %v", envelope)
	*/

	// read body from response to string
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	t.Logf("Response: %s", buf.String())

}

func TestFindFoldersResponse(t *testing.T) {
	envelope := new(epa.Envelope)
	if err := xml.NewDecoder(strings.NewReader(findFoldersResponse)).Decode(&envelope); err != nil {
		t.Fatalf("Error unmarshaling response: %v", err)
	}

	fmt.Printf("Envelope: %s\n", reflect.TypeOf(envelope.Body.Content))

	if content, ok := envelope.Body.Content.(epa.AdhocQueryResponse); ok {
		t.Logf("Content: %v", content)
	} else {
		t.Fatalf("Content is not of type AdhocQueryResponse")
	}

	//adhocResp := envelope.Body.Content.(epa.AdhocQueryResponse)
	// t.Logf("AdhocQueryResponse: %d", len(adhocResp.RegistryObjectList))
}
