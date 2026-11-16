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

package tipki

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// Bundle is trust material as ti writes it: roots.json, the TSL, its detached signature and its
// signer's OCSP response, in one file, for use without a network. It is not signed and needs no
// signature, since every part is verified on use; its fields only say what to verify (BUNDLE-001).
type Bundle struct {
	// Label describes the bundle and is not interpreted.
	Label string
	// AnchorSHA256 is the hash of the DER trust anchor it was exported for.
	AnchorSHA256 [32]byte
	Roots        []byte
	TSL          []byte
	// TSLSignature is the list's detached signature; a bundle without one cannot verify.
	TSLSignature []byte
	// TSLSignerStatus is the OCSP response for the list's signer; nil if the bundle has none.
	TSLSignerStatus []byte
	// FetchedAt is the older fetch time of roots.json and the TSL, from which the bundle's age counts.
	FetchedAt time.Time
}

const bundleFormatVersion = 2

// ParseBundle decodes a bundle. Like ti-pki it takes no unknown fields, no repeated ones and no other
// spelling of a field's name.
func ParseBundle(data []byte) (*Bundle, error) {
	fields, err := strictObject(data,
		[]string{"format_version", "label", "anchor_sha256", "roots", "tsl", "roots_meta", "tsl_meta"},
		[]string{"tsl_sig", "tsl_sig_meta", "tsl_ocsp", "tsl_ocsp_meta"})
	if err != nil {
		return nil, fmt.Errorf("tipki: bundle: %w", err)
	}
	bundle, err := decodeBundle(fields)
	if err != nil {
		return nil, fmt.Errorf("tipki: bundle: %w", err)
	}
	return bundle, nil
}

func decodeBundle(fields map[string]jsontext.Value) (*Bundle, error) {
	var version uint32
	if err := json.Unmarshal(fields["format_version"], &version); err != nil {
		return nil, &decodeError{what: "format_version", err: err}
	}
	if version != bundleFormatVersion {
		return nil, fmt.Errorf("unsupported format version %d", version)
	}
	bundle := new(Bundle)
	if bytes.Equal(fields["label"], []byte("null")) {
		return nil, errors.New("label: null")
	}
	if err := json.Unmarshal(fields["label"], &bundle.Label); err != nil {
		return nil, &decodeError{what: "label", err: err}
	}
	var anchor string
	if err := json.Unmarshal(fields["anchor_sha256"], &anchor); err != nil {
		return nil, &decodeError{what: "anchor_sha256", err: err}
	}
	digest, err := hex.DecodeString(anchor)
	if err != nil || len(digest) != len(bundle.AnchorSHA256) {
		return nil, errors.New("anchor_sha256 must be 64 hex digits")
	}
	copy(bundle.AnchorSHA256[:], digest)

	if bundle.Roots, err = bodyField(fields, "roots"); err != nil {
		return nil, err
	}
	if bundle.TSL, err = bodyField(fields, "tsl"); err != nil {
		return nil, err
	}
	rootsAt, err := metaField(fields["roots_meta"])
	if err != nil {
		return nil, fmt.Errorf("roots_meta: %w", err)
	}
	tslAt, err := metaField(fields["tsl_meta"])
	if err != nil {
		return nil, fmt.Errorf("tsl_meta: %w", err)
	}
	bundle.FetchedAt = time.Unix(min(rootsAt, tslAt), 0).UTC()

	present := func(name string) bool {
		value, ok := fields[name]
		return ok && !bytes.Equal(value, []byte("null"))
	}
	if !present("tsl_sig") || !present("tsl_sig_meta") {
		if present("tsl_sig") || present("tsl_sig_meta") {
			return nil, errors.New("tsl_sig and tsl_sig_meta come together")
		}
		return nil, errors.New("no detached signature: this bundle cannot verify, export it again")
	}
	if bundle.TSLSignature, err = bodyField(fields, "tsl_sig"); err != nil {
		return nil, err
	}
	if _, err := metaField(fields["tsl_sig_meta"]); err != nil {
		return nil, fmt.Errorf("tsl_sig_meta: %w", err)
	}
	if present("tsl_ocsp") != present("tsl_ocsp_meta") {
		return nil, errors.New("tsl_ocsp and tsl_ocsp_meta come together")
	}
	if present("tsl_ocsp") {
		if bundle.TSLSignerStatus, err = bodyField(fields, "tsl_ocsp"); err != nil {
			return nil, err
		}
		if _, err := metaField(fields["tsl_ocsp_meta"]); err != nil {
			return nil, fmt.Errorf("tsl_ocsp_meta: %w", err)
		}
	}
	return bundle, nil
}

// CheckAnchor says whether the bundle was exported for this DER trust anchor. Checking first gives a
// bundle of another environment a clear refusal, ahead of a signature that does not verify.
func (b *Bundle) CheckAnchor(anchorDER []byte) error {
	if sha256.Sum256(anchorDER) != b.AnchorSHA256 {
		return errors.New("tipki: the bundle belongs to a different trust anchor")
	}
	return nil
}

func bodyField(fields map[string]jsontext.Value, name string) ([]byte, error) {
	var encoded string
	if bytes.Equal(fields[name], []byte("null")) {
		return nil, fmt.Errorf("%s: null", name)
	}
	if err := json.Unmarshal(fields[name], &encoded); err != nil {
		return nil, &decodeError{what: name, err: err}
	}
	body, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || bytes.ContainsAny([]byte(encoded), "\r\n") {
		return nil, fmt.Errorf("%s: not base64", name)
	}
	return body, nil
}

var bundleSources = []string{"http", "file", "bundle", "cache", "embedded"}

func metaField(raw jsontext.Value) (int64, error) {
	fields, err := strictObject(raw, []string{"fetched_at", "source"}, []string{"etag", "last_modified", "max_age_secs"})
	if err != nil {
		return 0, err
	}
	var fetchedAt, maxAge *uint64
	var source string
	var etag, lastModified *string
	if bytes.Equal(fields["fetched_at"], []byte("null")) || bytes.Equal(fields["source"], []byte("null")) {
		return 0, errors.New("a required field is null")
	}
	if err := json.Unmarshal(fields["fetched_at"], &fetchedAt); err != nil {
		return 0, &decodeError{what: "fetched_at", err: err}
	}
	if err := json.Unmarshal(fields["source"], &source); err != nil {
		return 0, &decodeError{what: "source", err: err}
	}
	if !slices.Contains(bundleSources, source) {
		return 0, errors.New("source: not one of the known sources")
	}
	for name, into := range map[string]any{"etag": &etag, "last_modified": &lastModified, "max_age_secs": &maxAge} {
		if value, ok := fields[name]; ok {
			if err := json.Unmarshal(value, into); err != nil {
				return 0, &decodeError{what: name, err: err}
			}
		}
	}
	const maxFetchedAt = 1 << 40 // far beyond any real time, and safely inside time.Time
	if *fetchedAt > maxFetchedAt {
		return maxFetchedAt, nil
	}
	return int64(*fetchedAt), nil
}

// decodeError is a JSON value of a bundle or a roots.json that did not decode. Its text names the field, never the
// input: the decoder's own message quotes member names and values (servers.md rule 14). The decoder's error stays
// reachable through errors.Is and errors.As, so a caller can still tell why.
type decodeError struct {
	what string
	err  error
}

func (e *decodeError) Error() string { return e.what + ": does not decode" }

func (e *decodeError) Unwrap() error { return e.err }

// strictObject reads one JSON object whose keys are exactly as given, each at most once.
func strictObject(data []byte, required, optional []string) (map[string]jsontext.Value, error) {
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	if decoder.PeekKind() != '{' {
		return nil, errors.New("not an object")
	}
	if _, err := decoder.ReadToken(); err != nil {
		return nil, &decodeError{what: "object", err: err}
	}
	fields := make(map[string]jsontext.Value)
	for decoder.PeekKind() != '}' {
		token, err := decoder.ReadToken()
		if errors.Is(err, jsontext.ErrDuplicateName) {
			return nil, errors.New("repeated field")
		}
		if err != nil {
			return nil, &decodeError{what: "object", err: err}
		}
		name := token.String()
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return nil, errors.New("unknown field")
		}
		value, err := decoder.ReadValue()
		if err != nil {
			return nil, &decodeError{what: "object", err: err}
		}
		fields[name] = value.Clone()
	}
	if _, err := decoder.ReadToken(); err != nil {
		return nil, &decodeError{what: "object", err: err}
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the object")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("missing field %q", name)
		}
	}
	return fields, nil
}
