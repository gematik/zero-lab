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

// Package bundlefile hands out the trust material of a bundle file a producer writes and the deployment
// mounts, a Kubernetes ConfigMap or Secret most of the time (servers.md rule 8). It is the host-side piece
// beside the sans-I/O core, as package fetch is for a host that downloads: tipki verifies, this package reads
// the file.
//
// A [Trust] loads the file at the start, which must succeed, and reads it again on [Trust.Reload] and, if the
// host sets an interval, in the background. What it compares is the file's content, read through the path
// each time: a ConfigMap update repoints a symlink, so neither the path's modification time nor an open handle
// says that the material changed. A file that cannot be read, a bundle that does not verify, one fetched
// before the bundle in use, or a list older than the one in use (TSLSIG-053) never replaces the store in use.
// That store stands for [tipki.MaxBundleAge] from the bundle's fetched_at and never past the list's
// NextUpdate, and after that [Trust.Current] fails closed, as it does when no bundle has ever loaded.
//
// The file may be gzipped. `ti pki trust export` writes about 800 kB of JSON, and a ConfigMap holds 1 MiB with
// everything else in it; gzipped, a bundle is about 190 kB. A file that starts with the gzip magic is read as
// exactly one gzip member, with nothing after it, and is refused once it would decompress to more than 16 MiB,
// the bound a plain bundle has. Compression is only transport: what is decompressed is the bundle format of
// BUNDLE-001 and passes every check a plain file passes.
package bundlefile
