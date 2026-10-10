package ti

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// IdentitySource says where `ti` finds the SMC-B AUT identity: a PKCS#12 file, a PEM
// certificate and key, or a card at the Konnektor. Exactly one of the three.
type IdentitySource struct {
	// P12Path is a PKCS#12 file; P12PasswordPath a file whose first line is its password
	// (default 00). P12Password passes the password itself and is for interactive use
	// only: it shows in the process list.
	P12Path         string
	P12PasswordPath string
	P12Password     string
	// CertPath (the certificate, then its chain) and KeyPath (PKCS#8 or EC PRIVATE KEY).
	CertPath string
	KeyPath  string
	// Card at the Konnektor (ICCSN, Telematik-ID or handle); Connector names the .kon
	// configuration, else the one `ti connector use` selected.
	Card      string
	Connector string
}

// Args are the identity options of the `identity` and `idpd` commands.
func (s IdentitySource) Args() ([]string, error) {
	switch {
	case s.P12Path != "":
		if s.CertPath != "" || s.KeyPath != "" || s.Card != "" {
			return nil, fmt.Errorf("identity: one source only (P12Path given)")
		}
		args := []string{"--p12", s.P12Path}
		if s.P12PasswordPath != "" {
			args = append(args, "--p12-password-path", s.P12PasswordPath)
		} else if s.P12Password != "" {
			args = append(args, "--p12-password", s.P12Password)
		}
		return args, nil
	case s.CertPath != "" || s.KeyPath != "":
		if s.CertPath == "" || s.KeyPath == "" {
			return nil, fmt.Errorf("identity: CertPath and KeyPath go together")
		}
		if s.Card != "" {
			return nil, fmt.Errorf("identity: one source only (CertPath given)")
		}
		return []string{"--cert", s.CertPath, "--key", s.KeyPath}, nil
	case s.Card != "":
		args := []string{"--card", s.Card}
		if s.Connector != "" {
			args = append(args, "--connector", s.Connector)
		}
		return args, nil
	default:
		return nil, fmt.Errorf("identity: no source (P12Path, CertPath+KeyPath or Card)")
	}
}

// String names the source for logs and reports, without secrets.
func (s IdentitySource) String() string {
	switch {
	case s.P12Path != "":
		return s.P12Path
	case s.CertPath != "":
		return s.CertPath + " + " + s.KeyPath
	case s.Card != "":
		if s.Connector != "" {
			return s.Connector + " card " + s.Card
		}
		return "card " + s.Card
	}
	return "no identity"
}

// Admission is the certificate's admission statement: who the TI issued it to. The JSON
// shape is the one the ePA proxy's /info has always shown.
type Admission struct {
	ProfessionItems    []string `json:"professionItems"`
	ProfessionOIDs     []string `json:"professionOids"`
	RegistrationNumber string   `json:"registrationNumber"`
}

// Identity is the AUT identity `ti identity inspect` selected from a source: its
// certificate, and signing through the tool. The private key stays with the tool.
type Identity struct {
	runner      Runner
	source      IdentitySource
	subject     string
	telematikID string
	curve       string
	certDER     []byte
	admission   *Admission
}

type inspectReport struct {
	TelematikID *string `json:"telematik_id"`
	Signing     struct {
		Curve string `json:"curve"`
	} `json:"signing"`
	Certificate struct {
		Subject   string `json:"subject"`
		PEM       string `json:"pem"`
		Admission *struct {
			ProfessionItems []string `json:"profession_items"`
			ProfessionOIDs  []struct {
				OID string `json:"oid"`
			} `json:"profession_oids"`
			RegistrationNumber *string `json:"registration_number"`
		} `json:"admission"`
	} `json:"certificate"`
}

// NewIdentity selects the identity in source and reads its certificate.
func NewIdentity(ctx context.Context, runner Runner, source IdentitySource) (*Identity, error) {
	args, err := source.Args()
	if err != nil {
		return nil, err
	}
	out, err := runner.Run(ctx, nil, append([]string{"identity", "inspect"}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("identity %s: %w", source, err)
	}
	var report inspectReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("identity inspect: %w", err)
	}
	block, _ := pem.Decode([]byte(report.Certificate.PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("identity inspect: no certificate PEM in the report")
	}
	id := &Identity{
		runner:  runner,
		source:  source,
		subject: report.Certificate.Subject,
		curve:   report.Signing.Curve,
		certDER: block.Bytes,
	}
	if report.TelematikID != nil {
		id.telematikID = *report.TelematikID
	}
	if a := report.Certificate.Admission; a != nil {
		oids := make([]string, 0, len(a.ProfessionOIDs))
		for _, oid := range a.ProfessionOIDs {
			oids = append(oids, oid.OID)
		}
		id.admission = &Admission{ProfessionItems: a.ProfessionItems, ProfessionOIDs: oids}
		if a.RegistrationNumber != nil {
			id.admission.RegistrationNumber = *a.RegistrationNumber
		}
	}
	return id, nil
}

// Source is where the identity came from.
func (i *Identity) Source() IdentitySource { return i.source }

// Subject is the certificate's subject DN, RFC 4514.
func (i *Identity) Subject() string { return i.subject }

// CommonName is the subject's CN.
func (i *Identity) CommonName() string { return commonName(i.subject) }

// TelematikID is the admission statement's registration number, empty without one.
func (i *Identity) TelematikID() string { return i.telematikID }

// Curve is the key's curve, e.g. brainpoolP256r1.
func (i *Identity) Curve() string { return i.curve }

// CertificateDER is the AUT certificate.
func (i *Identity) CertificateDER() []byte { return i.certDER }

// Admission is the certificate's admission statement, nil without one.
func (i *Identity) Admission() *Admission { return i.admission }

// SignJWT signs claims as a compact JWS: `alg` from the key (ES256 unless header names
// BP256R1), `x5c` the certificate, `typ` and the other header members from header.
func (i *Identity) SignJWT(ctx context.Context, header map[string]any, claims map[string]any) (string, error) {
	args, err := i.source.Args()
	if err != nil {
		return "", err
	}
	args = append([]string{"identity", "sign", "--claims", "-"}, args...)
	for name, value := range header {
		switch name {
		case "typ":
			args = append(args, "--typ", fmt.Sprint(value))
		case "alg":
			args = append(args, "--alg", fmt.Sprint(value))
		case "x5c":
			// The tool sets it from the certificate.
		default:
			encoded, err := json.Marshal(value)
			if err != nil {
				return "", fmt.Errorf("header %s: %w", name, err)
			}
			args = append(args, "--header", name+"="+string(encoded))
		}
	}
	stdin, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}
	out, err := i.runner.Run(ctx, stdin, args...)
	if err != nil {
		return "", fmt.Errorf("sign with %s: %w", i.source, err)
	}
	var report struct {
		JWS string `json:"jws"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return "", fmt.Errorf("identity sign: %w", err)
	}
	return report.JWS, nil
}

// commonName is the CN of an RFC 4514 DN, or the DN itself without one.
func commonName(dn string) string {
	for part := range strings.SplitSeq(dn, ",") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return value
		}
	}
	return dn
}
