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

// Package fetch downloads an environment's TI trust material and keeps it current, for a host that has no
// producer to mount a bundle from (decision-12). It is the host-side piece beside the sans-I/O core: tipki
// verifies, this package does the I/O, and only over the *http.Client the host hands it, so the host keeps
// the transport and its proxies and the core keeps trust.
//
// Nothing downloaded is trusted for where it came from. The hosts are fixed per environment, a redirect is
// not followed, and the list travels over plain HTTP as gemSpec_TSL A_21175 mandates: what makes the
// material trustworthy is that it passes the checks a mounted bundle passes, the roots and the list's
// detached signature under the environment's anchors, and the list's SHA-256 named by the HTTPS host
// (A_30044), since a signature alone cannot say a list is the newest.
//
// A [Trust] fetches once at the start, which must succeed, and then in the background. Readers never fetch:
// [Trust.Current] and [Trust.Source] hand out the copy in memory, which stands for [tipki.MaxBundleAge] from
// its last good refresh and never past the list's NextUpdate, and after that fails closed.
package fetch
