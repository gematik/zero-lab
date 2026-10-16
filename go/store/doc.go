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

// Package store implements spec/store, the sealed store the TI command-line tools share
// per profile: tokens, discovery documents, cached trust material and small state,
// readable and writable by every conformant implementation on the same files.
//
// A [Backend] keeps records as bytes with a namespace, a hashed name, an expiry and
// blind-index tags; it never holds a key. [MemoryBackend] is the in-process one; package
// filestore is the files backend. A [Keyring] holds a profile's data keys, unwrapped
// through a [KeyWrapper], and is the [Sealer] that turns ids into names, metadata into
// tags and payloads into sealed records. A [Store] puts the two together for the
// namespaces of the registry.
//
// The package reads no clock, environment variable or file: time is a parameter and
// randomness an [io.Reader].
package store
