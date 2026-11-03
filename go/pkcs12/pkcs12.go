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

package pkcs12

import "github.com/gematik/zero-lab/go/pkcs12/internal/syntax"

// Errors returned by this package. Callers test with errors.Is; the wrapped message adds the detail.
var (
	// ErrInvalidPFX reports input that is not a PKCS#12 PFX structure.
	ErrInvalidPFX = syntax.ErrInvalidPFX
	// ErrUnsupportedAlgorithm reports an algorithm or mode this package does not implement, e.g. the
	// public-key integrity or privacy mode.
	ErrUnsupportedAlgorithm = syntax.ErrUnsupportedAlgorithm
	// ErrParse reports a part of the structure that does not parse.
	ErrParse = syntax.ErrParse
	// ErrLimitExceeded reports an iteration count above the limit this package accepts, see the package
	// documentation.
	ErrLimitExceeded = syntax.ErrLimitExceeded
	// ErrDecryption reports ciphertext that does not decrypt: a wrong password in a file without MAC, or
	// corrupt data.
	ErrDecryption = syntax.ErrDecryption
	// ErrAuthentication reports a MAC mismatch: a wrong password or an altered file.
	ErrAuthentication = syntax.ErrAuthentication
	// ErrInvalidPadding reports invalid PKCS#7 padding after decryption; it comes wrapped together with
	// ErrDecryption.
	ErrInvalidPadding = syntax.ErrInvalidPadding
)

// The identifiers [EncodeOptions] takes.
var (
	OIDAes128CBC = syntax.OIDAes128CBC
	OIDAes192CBC = syntax.OIDAes192CBC
	OIDAes256CBC = syntax.OIDAes256CBC
	OIDSHA256    = syntax.OIDSHA256
	OIDSHA384    = syntax.OIDSHA384
	OIDSHA512    = syntax.OIDSHA512
)

// PFX is a parsed PKCS#12 file (RFC 7292 Section 4), before anything inside its authSafe is read.
type PFX = syntax.PFX

// ContentInfo is the type and content of [PFX.AuthSafe].
type ContentInfo = syntax.ContentInfo

// MacData is the integrity data of [PFX]; nil when the file has none.
type MacData = syntax.MacData

// DigestInfo is the MAC value and its algorithm in [MacData].
type DigestInfo = syntax.DigestInfo

// Parse reads the outer structure of a PKCS#12 file without a password, e.g. to insist on a MAC before
// decrypting: PFX.MacData is nil in a file without one.
func Parse(data []byte) (*PFX, error) { return syntax.Parse(data) }

// VerifyMAC checks the MAC of pfx. A PFX without MacData has no integrity protection and passes; callers
// that require one check pfx.MacData.
func VerifyMAC(pfx *PFX, password []byte) error { return syntax.VerifyMAC(pfx, password) }
