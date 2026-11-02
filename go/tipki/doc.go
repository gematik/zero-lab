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

// Package tipki reads what the Telematikinfrastruktur states in a certificate: its type, its
// admission extension and what a validation profile requires of it. It follows Rust's ti-pki
// rule for rule (spec/pki-profiles), and a shared corpus holds the two together.
//
// It decides nothing about whether a certificate can be trusted. It does not build chains, read
// the TSL or ask OCSP responders, and every answer comes from the certificate's own, so far
// unauthenticated, content. A caller believes a certificate only after that has been established
// elsewhere. It takes a parsed certificate: use go/brainpool's parser for brainpool keys, which
// crypto/x509 refuses.
package tipki
