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

package zaddy

import (
	"errors"
	"slices"

	"github.com/gematik/zero-lab/go/pep"
)

// refuseSessionCookie refuses a policy with a SessionCookie enforcer at any depth (server rule 17). Such an
// enforcer admits zero-pep-proxy's session snapshots, and a snapshot outlives the sign-out that ended its
// session: without the revocations of zero-pep-proxy it would admit a signed-out session until it expires.
// zaddy has none since it keeps no database (TASK-443); a policy that cannot hold is refused at start rather
// than found in production.
func refuseSessionCookie(enforcer pep.Enforcer) error {
	if !usesSessionCookie(enforcer) {
		return nil
	}
	return errors.New("enforcer SessionCookie is not available in zaddy: it has no session revocations of zero-pep-proxy, " +
		"so a signed-out session would pass until its snapshot expires; protect the route with forward_auth to zero-pep-proxy's /oauth2/auth")
}

// usesSessionCookie reports whether enforcer is or holds a session cookie enforcer.
func usesSessionCookie(enforcer pep.Enforcer) bool {
	if enforcer == nil {
		return false
	}
	if holder, ok := enforcer.(*pep.EnforcerHolder); ok {
		return holder != nil && usesSessionCookie(holder.Enforcer)
	}
	if enforcer.Type() == pep.EnforcerTypeSessionCookie {
		return true
	}
	composite, ok := enforcer.(interface{ Enforcers() []pep.Enforcer })
	if !ok {
		return false
	}
	return slices.ContainsFunc(composite.Enforcers(), usesSessionCookie)
}
