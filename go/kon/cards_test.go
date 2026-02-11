package kon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSDS = `<?xml version="1.0" encoding="UTF-8"?>
<ConnectorSDS xmlns="http://ws.gematik.de/conn/ServiceDirectory/v3.1">
  <ProductInformation>
    <ProductTypeInformation>
      <ProductType>Konnektor</ProductType>
      <ProductTypeVersion>4.0.0</ProductTypeVersion>
    </ProductTypeInformation>
    <ProductIdentification>
      <ProductVendorID>Test</ProductVendorID>
      <ProductCode>TEST</ProductCode>
      <ProductVersion>
        <Local>
          <HWVersion>1.0.0</HWVersion>
          <FWVersion>1.0.0</FWVersion>
        </Local>
      </ProductVersion>
    </ProductIdentification>
  </ProductInformation>
  <ServiceInformation>
    <Service Name="EventService">
      <Abstract>EventService</Abstract>
      <Versions>
        <Version TargetNamespace="http://ws.gematik.de/conn/EventService/v7.2" Version="7.2.0">
          <Abstract>EventService v7.2</Abstract>
          <EndpointTLS Location="%%ENDPOINT%%/ws/EventService"/>
        </Version>
      </Versions>
    </Service>
  </ServiceInformation>
</ConnectorSDS>`

const testGetCardsResponse = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns4:GetCardsResponse xmlns:ns4="http://ws.gematik.de/conn/EventService/v7.2"
                          xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0"
                          xmlns:ns3="http://ws.gematik.de/conn/CardService/v8.1"
                          xmlns:ns5="http://ws.gematik.de/conn/CardServiceCommon/v2.0">
      <ns2:Status>
        <Result>OK</Result>
      </ns2:Status>
      <ns3:Cards>
        <ns3:Card>
          <ns2:CardHandle>card-smcb-1</ns2:CardHandle>
          <ns5:CardType>SMC-B</ns5:CardType>
          <ns5:Iccsn>80276123456789010001</ns5:Iccsn>
          <ns5:CtId>CT_ID_1</ns5:CtId>
          <ns5:SlotId>1</ns5:SlotId>
          <InsertTime>2024-01-15T10:30:00Z</InsertTime>
          <CardHolderName>Test Practice</CardHolderName>
        </ns3:Card>
        <ns3:Card>
          <ns2:CardHandle>card-hba-1</ns2:CardHandle>
          <ns5:CardType>HBA</ns5:CardType>
          <ns5:Iccsn>80276123456789020001</ns5:Iccsn>
          <ns5:CtId>CT_ID_1</ns5:CtId>
          <ns5:SlotId>2</ns5:SlotId>
          <InsertTime>2024-01-15T11:00:00Z</InsertTime>
          <CardHolderName>Dr. Test</CardHolderName>
        </ns3:Card>
      </ns3:Cards>
    </ns4:GetCardsResponse>
  </soap:Body>
</soap:Envelope>`

const testGetCardsFault = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Server</faultcode>
      <faultstring>internal error</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`

func newTestKonnektor(t *testing.T, eventServiceHandler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connector.sds":
			w.Header().Set("Content-Type", "text/xml")
			sds := strings.ReplaceAll(testSDS, "%%ENDPOINT%%", server.URL)
			w.Write([]byte(sds))
		case "/ws/EventService":
			eventServiceHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	config := &Dotkon{
		URL:            server.URL,
		MandantId:      "M1",
		ClientSystemId: "C1",
		WorkplaceId:    "W1",
	}

	client, err := NewClient(config)
	if err != nil {
		server.Close()
		t.Fatalf("creating client: %v", err)
	}

	return client, server
}

func TestGetCards(t *testing.T) {
	client, server := newTestKonnektor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("SOAPAction") != "http://ws.gematik.de/conn/EventService/v7.2#GetCards" {
			t.Errorf("unexpected SOAPAction: %s", r.Header.Get("SOAPAction"))
		}
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(testGetCardsResponse))
	})
	defer server.Close()

	cards, err := client.GetCards(context.Background())
	if err != nil {
		t.Fatalf("GetCards failed: %v", err)
	}

	if len(cards) != 2 {
		t.Fatalf("expected 2 cards, got %d", len(cards))
	}

	if cards[0].CardHandle != "card-smcb-1" {
		t.Errorf("expected CardHandle card-smcb-1, got %s", cards[0].CardHandle)
	}
	if cards[0].CardType != "SMC-B" {
		t.Errorf("expected CardType SMC-B, got %s", cards[0].CardType)
	}
	if cards[0].Iccsn != "80276123456789010001" {
		t.Errorf("expected Iccsn 80276123456789010001, got %s", cards[0].Iccsn)
	}
	if cards[0].CtId != "CT_ID_1" {
		t.Errorf("expected CtId CT_ID_1, got %s", cards[0].CtId)
	}
	if cards[0].CardHolderName != "Test Practice" {
		t.Errorf("expected CardHolderName 'Test Practice', got %s", cards[0].CardHolderName)
	}

	if cards[1].CardHandle != "card-hba-1" {
		t.Errorf("expected CardHandle card-hba-1, got %s", cards[1].CardHandle)
	}
	if cards[1].CardType != "HBA" {
		t.Errorf("expected CardType HBA, got %s", cards[1].CardType)
	}
}

func TestGetCards_Fault(t *testing.T) {
	client, server := newTestKonnektor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(testGetCardsFault))
	})
	defer server.Close()

	_, err := client.GetCards(context.Background())
	if err == nil {
		t.Fatal("expected error for SOAP fault")
	}

	expected := "GetCards SOAP fault: internal error"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}
