package dcappattest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/gematik/zero-lab/go/libzero/attestation/dcappattest"
)

const assertionTestData = "omlzaWduYXR1cmVYRjBEAiA8eM/dSDX36hN189RPxmRYXnIVb09hZZnbG/QCWSM5OAIgbfp650O1YUliQufgtvrvUmXPnUjBEYy9mYR+JwHI97hxYXV0aGVudGljYXRvckRhdGFYJfPWTs+IjMo6R9nqPnD9u6dLawuHA9ArlHDNlZnbdO8XQAAAAAE="

func TestAssertion(t *testing.T) {
	attestationClientDataHash := sha256.Sum256([]byte("challenge"))
	attestationData, err := base64.StdEncoding.DecodeString(attestationTestData)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := dcappattest.ParseAttestation([]byte(attestationData), attestationClientDataHash)
	if err != nil {
		t.Fatal(err)
	}
	assertionData, err := base64.StdEncoding.DecodeString(assertionTestData)
	if err != nil {
		t.Fatal(err)
	}

	assertionClientDataHash := sha256.Sum256([]byte("challenge"))

	assertion, err := dcappattest.ParseAssertion(assertionData, assertionClientDataHash, attestation.AttestationStatement.CredCert.PublicKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Assertion: %+v", assertion)
}
