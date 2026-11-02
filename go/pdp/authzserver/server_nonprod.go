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

package authzserver

import "uuid"

// NonProdStartSession stores session under a fresh ID, with no client authentication or policy check. Only the
// non-prod command calls it; no endpoint reaches it.
func (s *Server) NonProdStartSession(session *Session) error {
	session.ID = uuid.NewV4().String()
	return s.sessionStore.SaveAutzhServerSession(session)
}

// NonProdIssueTokens issues tokens for a stored session, with no client authentication or policy check. Only the
// non-prod command calls it; no endpoint reaches it.
func (s *Server) NonProdIssueTokens(sessionID string) (*TokenResponse, error) {
	session, err := s.sessionStore.GetAuthzServerSessionByID(sessionID)
	if err != nil {
		return nil, err
	}

	return s.issueOrRefreshTokens(session)
}
