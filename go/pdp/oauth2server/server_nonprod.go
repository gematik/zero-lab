package oauth2server

import "github.com/segmentio/ksuid"

// Non-production code for the OAuth2 server
func (s *Server) NonProdStartSession(session *AuthzServerSession) error {
	session.ID = ksuid.New().String()
	return s.sessionStore.SaveAutzhServerSession(session)
}

func (s *Server) NonProdIssueTokens(sessionId string) (*TokenResponse, error) {
	session, err := s.sessionStore.GetAuthzServerSessionByID(sessionId)
	if err != nil {
		return nil, err
	}

	return s.issueOrRefreshTokens(session)
}
