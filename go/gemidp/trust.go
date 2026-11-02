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

package gemidp

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
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
	// bundleRecheck is how long a loaded bundle stands before the list's own times are read again.
	bundleRecheck = time.Hour
	// maxBundleBytes bounds a mounted file; a list with its roots and signatures is about a megabyte.
	maxBundleBytes = 16 << 20
	// maxOCSPBytes bounds a responder's answer.
	maxOCSPBytes = 1 << 20
)

// BundleTrust checks a certificate against the bundle with the idpd-sig profile, and its revocation online
// (IDPV-005). It fails closed: a bundle that is missing, invalid or too old refuses every certificate, and
// the last good one is not used in its place.
type BundleTrust struct {
	bundlePath    string
	anchor        []byte
	signerAnchors [][]byte
	checker       tipki.RevocationChecker
	now           func() time.Time

	mu        sync.Mutex
	store     *tipki.TrustStore
	state     *tipki.TSLState
	modTime   time.Time
	size      int64
	fetchedAt time.Time
	loadedAt  time.Time
}

// NewBundleTrust loads the bundle at once, so a deployment without usable trust material does not start.
// bundlePath is the mounted file `ti pki trust export` writes, read again when it changes. httpClient carries
// the OCSP requests.
func NewBundleTrust(env Environment, bundlePath string, httpClient *http.Client) (*BundleTrust, error) {
	anchor, signerAnchors, err := anchorsFor(env)
	if err != nil {
		return nil, err
	}
	if bundlePath == "" {
		return nil, errors.New("no trust bundle: the IDP-Dienst's certificates cannot be verified without one")
	}
	trust := &BundleTrust{
		bundlePath:    bundlePath,
		anchor:        anchor,
		signerAnchors: signerAnchors,
		checker:       tipki.NewOCSPChecker(ocspTransport{httpClient}),
		now:           time.Now,
	}
	if _, err := trust.current(context.Background()); err != nil {
		return nil, err
	}
	return trust, nil
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

// Check implements [CertificateTrust].
func (t *BundleTrust) Check(ctx context.Context, which IDPCertificate, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%s: no certificate", which)
	}
	store, err := t.current(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", which, err)
	}
	validator := tipki.ProfileIdpdSig.Validator(store, tipki.CertFdSig, tipki.RevocationHardFail)
	result, err := validator.Validate(ctx, certs, t.now(), t.checker)
	if err != nil {
		return fmt.Errorf("%s: %w", which, err)
	}
	if result.Valid {
		return nil
	}
	reasons := make([]string, 0, len(result.Errors))
	for _, finding := range result.Errors {
		reasons = append(reasons, finding.Code+": "+finding.Message)
	}
	return fmt.Errorf("%s: %q is not valid for an IDP-Dienst: %s", which, certs[0].Subject.CommonName, strings.Join(reasons, "; "))
}

func (t *BundleTrust) current(ctx context.Context) (*tipki.TrustStore, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	info, err := os.Stat(t.bundlePath)
	if err != nil {
		t.store = nil
		return nil, fmt.Errorf("trust bundle: %w", err)
	}
	if t.store != nil && info.ModTime().Equal(t.modTime) && info.Size() == t.size &&
		now.Sub(t.loadedAt) < bundleRecheck && now.Sub(t.fetchedAt) < tipki.MaxBundleAge {
		return t.store, nil
	}
	t.store = nil
	store, fetchedAt, err := t.load(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("trust bundle: %w", err)
	}
	state := store.TSL.State()
	t.store, t.state, t.modTime, t.size, t.fetchedAt, t.loadedAt = store, &state, info.ModTime(), info.Size(), fetchedAt, now
	return store, nil
}

func (t *BundleTrust) load(ctx context.Context, now time.Time) (*tipki.TrustStore, time.Time, error) {
	file, err := os.Open(t.bundlePath)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(data) > maxBundleBytes {
		return nil, time.Time{}, fmt.Errorf("larger than %d bytes", maxBundleBytes)
	}
	bundle, err := tipki.ParseBundle(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	store, err := tipki.LoadTrustStore(bundle, t.anchor, t.signerAnchors, now, 0, t.state)
	if err != nil {
		return nil, time.Time{}, err
	}
	unqueried := slices.ContainsFunc(store.TSL.Warnings, func(warning *tipki.TSLError) bool { return warning.Code == "no_ocsp_check" })
	if unqueried {
		if err := store.TSL.CheckSignerStatus(ctx, t.checker); err != nil {
			return nil, time.Time{}, err
		}
	}
	return store, bundle.FetchedAt, nil
}

// ocspTransport carries OCSP over the client's HTTP. The answer proves itself, so plain HTTP is enough.
type ocspTransport struct{ client *http.Client }

func (o ocspTransport) Post(ctx context.Context, url, contentType, accept string, body []byte) ([]byte, error) {
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
