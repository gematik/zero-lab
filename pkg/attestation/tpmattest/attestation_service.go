package tpmattest

type Attestation struct {
	ID        string `json:"id"`
	AKRaw     []byte `json:"ak"`
	AKPub     []byte `json:"ak_pub"`
	AKCertRaw []byte `json:"ak_cert"`
	KeyRaw    []byte `json:"key"`
	CertRaw   []byte `json:"cert"`
}

type AttestationStore interface {
	SaveTPMAttestation(attestation *Attestation) error
	GetTPMAttestation(id string) (*Attestation, error)
}

type AttestationService interface {
}
