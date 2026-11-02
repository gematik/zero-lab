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

// Package tipki is the native Go side of the TI's PKI, as small as its flows allow. It follows Rust's
// ti-pki rule for rule, and shared corpora hold the two together (spec/pki-profiles, spec/pki-path).
//
// It reads what a certificate states: its type, its admission extension and what a validation profile
// requires of it. From the bundle ti writes, without a network, it walks the roots, verifies the TSL by
// its detached signature, and builds and checks a chain.
// [ParseCertificate] takes the brainpool keys crypto/x509 refuses, through go/brainpool. Package oid
// holds the identifiers of gemSpec_OID.
//
// OCSP goes through the caller's transport: chain building needs no network, revocation does. The
// pieces are not yet put together into one verdict (TASK-176), so a caller does that itself. Signatures are verified with ti-pki's
// algorithm set, ECDSA and RSA.
package tipki
