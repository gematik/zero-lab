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
// requires of it. It builds and checks a chain, without a network, from the bundle ti writes.
// [ParseCertificate] takes the brainpool keys crypto/x509 refuses, through go/brainpool. Package oid
// holds the identifiers of gemSpec_OID.
//
// None of this yet decides that a certificate can be trusted. The TSL and OCSP are still to come (TASK-176), and a caller believes a certificate only once they are established. The
// reading covers every type and profile of the TI; a chain's signatures are verified for ECDSA alone, so
// one with an RSA signature fails closed; the roots walk alone also admits RSA with SHA-256.
package tipki
