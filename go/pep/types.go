package pep

type ErrorType struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

var ErrorNotFound = ErrorType{
	HttpStatus:  404,
	Code:        "not_found",
	Description: "The requested resource could not be found",
}
