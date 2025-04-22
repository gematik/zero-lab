package dpop_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/segmentio/ksuid"
)

func TestSigning(t *testing.T) {
	privateKey, _ := dpop.NewPrivateKey()

	token := dpop.DPoP{
		Id:         ksuid.New().String(),
		HttpMethod: "GET",
		HttpURI:    "https://example.com/resource/1",
		IssuedAt:   time.Now(),
	}

	signed, err := token.Sign(privateKey)
	if err != nil {
		t.Error("expected nil, got ", err)
	}

	parsedToken, err := dpop.Parse(signed)

	if err != nil {
		t.Fatal("expected nil, got ", err)
	}

	t.Logf("%+v", parsedToken)
}

type testSpec struct {
	scenario     string
	dpopTemplate dpop.DPoP
	options      dpop.ParseOptions
	accessToken  string
	method       string
	uri          string
	nonce        string
	shouldFail   bool
}

func TestParseRequest(t *testing.T) {
	tests := []testSpec{
		{
			scenario: "valid dpop proof",
			dpopTemplate: dpop.DPoP{
				HttpMethod: "GET",
				HttpURI:    "https://example.com/resource/1",
			},
			method: "GET",
			uri:    "https://example.com/resource/1",
			options: dpop.ParseOptions{
				MaxAge: time.Minute,
			},
		},
		{
			scenario: "valid request uri",
			dpopTemplate: dpop.DPoP{
				HttpMethod: "GET",
				HttpURI:    "https://example.com/resource/1",
			},
			method: "GET",
			uri:    "https://example.com/resource/2",
			options: dpop.ParseOptions{
				MaxAge: time.Minute,
			},
			shouldFail: true,
		},
		{
			scenario: "invalid method",
			dpopTemplate: dpop.DPoP{
				HttpMethod: "POST",
				HttpURI:    "https://example.com/resource/1",
			},
			method: "GET",
			uri:    "https://example.com/resource/1",
			options: dpop.ParseOptions{
				MaxAge: time.Minute,
			},
			shouldFail: true,
		},
		{
			scenario: "missing nonce",
			dpopTemplate: dpop.DPoP{
				HttpMethod: "GET",
				HttpURI:    "https://example.com/resource/1",
			},
			method: "GET",
			uri:    "https://example.com/resource/1",
			options: dpop.ParseOptions{
				MaxAge:        time.Minute,
				NonceRequired: true,
			},
			shouldFail: true,
		},
		{
			scenario: "valid nonce",
			dpopTemplate: dpop.DPoP{
				HttpMethod: "GET",
				HttpURI:    "https://example.com/resource/1",
				Nonce:      "nonce123",
			},
			method: "GET",
			uri:    "https://example.com/resource/1",
			options: dpop.ParseOptions{
				MaxAge:        time.Minute,
				NonceRequired: true,
			},
			nonce: "nonce123",
		},
	}

	for _, test := range tests {
		privateKey, _ := dpop.NewPrivateKey()

		builder := dpop.NewBuilder().
			Id(ksuid.New().String()).
			HttpMethod(test.dpopTemplate.HttpMethod).
			HttpURI(test.dpopTemplate.HttpURI)

		if test.dpopTemplate.Nonce != "" {
			builder.Nonce(test.dpopTemplate.Nonce)
		}
		if test.accessToken != "" {
			builder.AccessTokenHashFrom(test.accessToken)
		}

		proof, err := builder.Build()
		if err != nil {
			t.Fatal("expected nil, got ", err)
		}

		signedProof, err := proof.Sign(privateKey)
		if err != nil {
			t.Error("expected nil, got ", err)
		}

		request, err := http.NewRequest(test.method, test.uri, nil)
		if err != nil {
			t.Fatal("expected nil, got ", err)
		}

		request.Header.Set("DPoP", signedProof)

		if test.accessToken != "" {
			request.Header.Set("Authorization", "DPoP "+test.accessToken)
		}

		_, dpopErr := dpop.ParseRequest(request, test.options)
		if dpopErr != nil {
			if !test.shouldFail {
				t.Fatal("expected nil, got ", dpopErr)
			}
			continue
		}
		if test.shouldFail {
			t.Fatal("expected error, got nil")
		}

	}

}
