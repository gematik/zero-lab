package epa

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Envelope represents the top-level SOAP envelope
type Envelope struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
	Header  Header   `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
	Body    Body     `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
}

// Header represents the SOAP header
type Header struct {
	Action    string `xml:"http://www.w3.org/2005/08/addressing Action"`
	MessageID string `xml:"http://www.w3.org/2005/08/addressing MessageID"`
	To        string `xml:"http://www.w3.org/2005/08/addressing To"`
	RelatesTo string `xml:"http://www.w3.org/2005/08/addressing RelatesTo"`
}

// Body represents the SOAP body
type Body struct {
	Content interface{}
}

// UnmarshalXML dynamically parses the Body content based on the element type
func (b *Body) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Create a loop to consume tokens until the end of the <Body> element
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch tok := t.(type) {
		case xml.StartElement:
			// Handle known types based on the element name
			switch tok.Name.Local {
			case "AdhocQueryResponse":
				var response AdhocQueryResponse
				if err := d.DecodeElement(&response, &tok); err != nil {
					return err
				}
				b.Content = response
				continue // Continue to consume the rest of the <Body>
			default:
				return fmt.Errorf("unsupported element: %s %s", tok.Name.Space, tok.Name.Local)
			}
		case xml.EndElement:
			// Exit when we reach the end of the <Body> element
			if tok.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}

// MarshalXML dynamically encodes the Body content
func (b *Body) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if b.Content == nil {
		return nil
	}

	// Marshal based on the actual type of Content
	switch content := b.Content.(type) {
	case AdhocQueryResponse:
		return e.EncodeElement(content, start)
	default:
		return errors.New("unsupported content type for marshaling")
	}
}

func (rl *RegistryObjectList) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	rl.Items = make([]interface{}, 0)
	// Create a loop to consume tokens until the end of the <RegistryObjectList> element
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch tok := t.(type) {
		case xml.StartElement:
			// Handle known types based on the element name
			switch tok.Name.Local {
			case "RegistryPackage":
				var pkg RegistryPackage
				if err := d.DecodeElement(&pkg, &tok); err != nil {
					return err
				}
				rl.Items = append(rl.Items, pkg)
			default:
				return fmt.Errorf("unsupported element: %s %s", tok.Name.Space, tok.Name.Local)
			}
		case xml.EndElement:
			// Exit when we reach the end of the <RegistryObjectList> element
			if tok.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}
