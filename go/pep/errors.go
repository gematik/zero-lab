package pep

import "fmt"

type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s (code=%s)", e.Description, e.Code)
}

var ErrForbiddenHeadersInRequest = Error{
	HttpStatus:  400,
	Code:        "forbidden_headers_in_request",
	Description: "Request contains forbidden headers",
}

var ErrNoAuthorizationHeader = Error{
	HttpStatus:  400,
	Code:        "no_authorization_header",
	Description: "No Authorization header in request",
}

var ErrInvalidAuthorizationHeader = Error{
	HttpStatus:  400,
	Code:        "invalid_authorization_header",
	Description: "Invalid Authorization header in request",
}

func ErrorAccessDeinied(description string) Error {
	return Error{
		HttpStatus:  403,
		Code:        "access_denied",
		Description: description,
	}
}
