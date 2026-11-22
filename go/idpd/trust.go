// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package idpd

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
	"github.com/gematik/zero-lab/go/tipki/bundlefile"
)

// IDPCertificate names one of the IDP-Dienst's certificates, as the IDP names its keys.
type IDPCertificate string

const (
	// DiscoverySigner signs the discovery document.
	DiscoverySigner IDPCertificate = "puk_disc_sig"
	// TokenSigner signs challenges and tokens.
	TokenSigner IDPCertificate = "puk_idp_sig" //nolint:gosec // the public name of a key at the IDP, not a credential
)

// CertificateTrust decides about the IDP-Dienst's certificates. There is no way to go without it: a key
// is used only after Check returned nil for its certificate.
type CertificateTrust interface {
	// Check returns why certs[0] is not to be trusted as which; certs[1:] is the rest of its x5c.
	Check(ctx context.Context, which IDPCertificate, certs []*x509.Certificate) error
}

const (
	// bundleReread is how often the mounted bundle is read again: a ConfigMap update reaches the pod within
	// about a minute, and a read that finds the same content costs a hash.
	bundleReread = time.Minute
	// bundleLoadTimeout bounds the first load, the TSL signer's responder included.
	bundleLoadTimeout = 2 * time.Minute
	// maxOCSPBytes bounds a responder's answer.
	maxOCSPBytes = 1 << 20
)

// TrustOption adjusts [NewFetchingTrust] and [NewBundleTrust].
type TrustOption func(*trustSettings)

type trustSettings struct {
	mark   func(context.Context) context.Context
	logger *slog.Logger
}

// WithSelfVerifying marks the fetches of data that proves itself (OCSP answers, and with [NewFetchingTrust] the
// TSL, which A_21175 publishes over plain http) with mark, so that an HTTP client which refuses plain http
// otherwise lets them through: go/egress's SelfVerifying fits. A function, so that this package imports no
// transport; nil leaves the requests as they are.
func WithSelfVerifying(mark func(context.Context) context.Context) TrustOption {
	return func(s *trustSettings) { s.mark = mark }
}

// WithTrustLogger has [NewFetchingTrust]'s background refresh log a failed download to logger; without it nothing
// is logged (go/docs/design.md section 2).
func WithTrustLogger(logger *slog.Logger) TrustOption {
	return func(s *trustSettings) { s.logger = logger }
}

func trustOptions(opts []TrustOption) trustSettings {
	var settings trustSettings
	for _, opt := range opts {
		opt(&settings)
	}
	return settings
}

// verifier is what both sources of trust material share: the anchors the environment picked, and the checks.
type verifier struct {
	anchor        []byte
	signerAnchors [][]byte
	checker       tipki.RevocationChecker
	now           func() time.Time
}

func newVerifier(env Environment, httpClient *http.Client, mark func(context.Context) context.Context) (verifier, error) {
	anchor, signerAnchors, err := anchorsFor(env)
	if err != nil {
		return verifier{}, err
	}
	return verifier{
		anchor:        anchor,
		signerAnchors: signerAnchors,
		checker:       tipki.NewOCSPChecker(ocspTransport{client: httpClient, mark: mark}),
		now:           time.Now,
	}, nil
}

func (v *verifier) check(ctx context.Context, store *tipki.TrustStore, which IDPCertificate, certs []*x509.Certificate) error {
	validator := tipki.ProfileIdpdSig.Validator(store, tipki.CertFdSig, tipki.RevocationHardFail)
	result, err := validator.Validate(ctx, certs, v.now(), v.checker)
	if err != nil {
		return fmt.Errorf("%s: %w", which, err)
	}
	if result.Valid {
		return nil
	}
	reasons := make([]string, 0, len(result.Errors))
	for _, finding := range result.Errors {
		reasons = append(reasons, string(finding.Code)+": "+finding.Message)
	}
	return fmt.Errorf("%s: %q is not valid for an IDP-Dienst: %s", which, certs[0].Subject.CommonName, strings.Join(reasons, "; "))
}

// BundleTrust checks a certificate against a mounted bundle with the idpd-sig profile, and its revocation
// online (IDPV-005), through [bundlefile.Trust]. A bundle missing or invalid at the start does not start; a
// replacement that is missing, invalid or older does not replace the bundle in use, which stands until it is too
// old (BUNDLE-003) or its list's NextUpdate has passed, and then every certificate is refused.
type BundleTrust struct {
	verifier
	file *bundlefile.Trust
}

// NewBundleTrust loads the bundle at once, so a deployment without usable trust material does not start.
// bundlePath is the mounted file `ti pki trust export` writes, plain or gzipped, read again every minute until
// [BundleTrust.Close]. httpClient carries the OCSP requests; logger receives the bundles that were loaded and
// those that were not, and may be nil.
func NewBundleTrust(env Environment, bundlePath string, httpClient *http.Client, logger *slog.Logger, opts ...TrustOption) (*BundleTrust, error) {
	base, err := newVerifier(env, httpClient, trustOptions(opts).mark)
	if err != nil {
		return nil, err
	}
	return newBundleTrust(base, bundlePath, logger)
}

func newBundleTrust(base verifier, bundlePath string, logger *slog.Logger) (*BundleTrust, error) {
	if bundlePath == "" {
		return nil, errors.New("no trust material: the IDP-Dienst's certificates cannot be verified without trust_fetch or trust_bundle_path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), bundleLoadTimeout)
	defer cancel()
	file, err := bundlefile.New(ctx, bundlefile.Config{
		Path:          bundlePath,
		Anchor:        base.anchor,
		SignerAnchors: base.signerAnchors,
		Checker:       base.checker,
		Interval:      bundleReread,
		Logger:        logger,
		Clock:         base.now,
	})
	if err != nil {
		return nil, fmt.Errorf("trust bundle: %w", err)
	}
	return &BundleTrust{verifier: base, file: file}, nil
}

// Close ends the background reads. The bundle in use stands until it is too old.
func (t *BundleTrust) Close() {
	t.file.Close()
}

// anchorsFor picks what the environment trusts (IDPV-006). Only a named environment picks anything: with
// TEST-ONLY anchors in every build, a default here would be trust nobody chose.
func anchorsFor(env Environment) ([]byte, [][]byte, error) {
	switch env {
	case EnvironmentProduction:
		return tipki.AnchorProd, [][]byte{tipki.TSLSignerAnchorProd}, nil
	case EnvironmentTest, EnvironmentReference:
		return tipki.AnchorNonProd, [][]byte{tipki.TSLSignerAnchorNonProd}, nil
	default:
		return nil, nil, errors.New("no IDP-Dienst environment: name test, ref or prod")
	}
}

// Check implements [CertificateTrust]. It never reads the file.
func (t *BundleTrust) Check(ctx context.Context, which IDPCertificate, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%s: no certificate", which)
	}
	store, err := t.file.Current()
	if err != nil {
		return fmt.Errorf("%s: %w", which, err)
	}
	return t.check(ctx, store, which, certs)
}

// ocspTransport carries OCSP over the client's HTTP. The answer proves itself, so plain HTTP is enough, and mark,
// when the host gave one, says so to its client.
type ocspTransport struct {
	client *http.Client
	mark   func(context.Context) context.Context
}

func (o ocspTransport) Post(ctx context.Context, url, contentType, accept string, body []byte) ([]byte, error) {
	if o.mark != nil {
		ctx = o.mark(ctx)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", accept)
	response, err := o.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("responder answered %d", response.StatusCode)
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxOCSPBytes+1))
	if err != nil {
		return nil, err
	}
	if len(answer) > maxOCSPBytes {
		return nil, fmt.Errorf("answer larger than %d bytes", maxOCSPBytes)
	}
	return answer, nil
}
