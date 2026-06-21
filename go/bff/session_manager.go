package bff

import (
	"time"
)

type Session struct {
	Id                   string         `json:"id"`
	State                string         `json:"state"`
	CreatedAt            time.Time      `json:"created_at"`
	CodeVerifier         string         `json:"code_verifier"`
	CodeChallengeMethod  string         `json:"code_challenge_method"`
	AccessToken          string         `json:"access_token"`
	AccessTokenExpiresAt time.Time      `json:"access_token_expires_at"`
	RefreshToken         string         `json:"refresh_token"`
	Identity             map[string]any `json:"identity,omitempty"`
}

type SessionManager interface {
	CreateSession(state string, codeVerifier string, codeChallengeMethod string) (*Session, error)
	UpdateSession(session *Session) error
	GetSessionByState(state string) (*Session, error)
	GetSessionById(id string) (*Session, error)
	DeleteSessionById(id string) error
}
