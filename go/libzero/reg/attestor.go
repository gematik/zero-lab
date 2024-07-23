package reg

type attestor interface {
	// VerifyMessageAttestation verifies the attestation of a message
	verifyMessageAttestation(message, format []byte, lastAttestation *AttestationEntity) (*AttestationEntity, error)
	// ValidateClientPosture validates if client posture matches the attestation
	validateClientPosture(client *ClientEntity) error
}

func getAttestor(format AttestationFormat) attestor {
	switch format {
	case AttestationFormatAppleAttestation:
		return &attestorAppleAttestation{}
	case AttestationFormatAppleAssertion:
		return &attestorAppleAssertion{}
	case AttestationFormatNone:
		return &attestorNone{}
	default:
		return nil
	}
}
