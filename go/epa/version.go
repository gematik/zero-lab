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

package epa

import (
	"runtime/debug"
	"strings"
)

// Version is the zero-epa release version. It defaults to "dev" and is overridden
// at build time via -ldflags "-X github.com/gematik/zero-lab/go/epa.Version=<v>".
// It ends up in the x-useragent header, which the ePA aggregators validate
// (ClientId/Version, version max 15 chars of [a-zA-Z0-9.-]) — so builds must
// inject a plain semantic version, not a raw `git describe` string.
var Version = "dev"

// ResolveVersion returns the ldflags-injected Version when set, otherwise the module
// version embedded by `go install …@vX.Y.Z` (read from the build info).
func ResolveVersion() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
	}
	return Version
}
