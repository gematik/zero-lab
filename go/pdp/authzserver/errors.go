package authzserver

import "fmt"

// Error is an OAuth 2.0 error response (RFC 6749 §5.2). HttpStatus carries the HTTP
// status code and is not serialized.
type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// oauthErr builds a pointer *Error with the given HTTP status, OAuth error code and
// description (RFC 6749 §5.2).
func oauthErr(status int, code, description string) *Error {
	return &Error{HttpStatus: status, Code: code, Description: description}
}
