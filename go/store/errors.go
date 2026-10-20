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

package store

import "fmt"

// Code is a result code of spec/store.
type Code string

// The result codes of spec/store.
const (
	CodeOK                  Code = "ok"
	CodeNotFound            Code = "not_found"
	CodeExpired             Code = "expired"
	CodeMalformed           Code = "malformed"
	CodeUnsupportedVersion  Code = "unsupported_version"
	CodeUnknownKid          Code = "unknown_kid"
	CodeAuthFailed          Code = "auth_failed"
	CodeLimitExceeded       Code = "limit_exceeded"
	CodeInvalidArgument     Code = "invalid_argument"
	CodeCapabilityMissing   Code = "capability_missing"
	CodeNoKeyring           Code = "no_keyring"
	CodeInsecurePermissions Code = "insecure_permissions"
	CodeBusy                Code = "busy"
	CodeBackendError        Code = "backend_error"
)

// Error is a store failure with its result code. errors.Is matches any *Error of the same
// code, so callers test against the sentinels below.
type Error struct {
	Code Code
	// What the code is about: "record", "keyring", "namespace", ...
	What string
	// Err is the underlying error of a backend_error, if any.
	Err error
}

func (e *Error) Error() string {
	switch {
	case e.Err != nil:
		return fmt.Sprintf("store: %s: %s: %v", e.Code, e.What, e.Err)
	case e.What != "":
		return fmt.Sprintf("store: %s: %s", e.Code, e.What)
	}
	return "store: " + string(e.Code)
}

// Is matches errors of the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func (e *Error) Unwrap() error { return e.Err }

// Sentinels for errors.Is.
var (
	ErrNotFound            = &Error{Code: CodeNotFound}
	ErrExpired             = &Error{Code: CodeExpired}
	ErrMalformed           = &Error{Code: CodeMalformed}
	ErrUnsupportedVersion  = &Error{Code: CodeUnsupportedVersion}
	ErrUnknownKid          = &Error{Code: CodeUnknownKid}
	ErrAuthFailed          = &Error{Code: CodeAuthFailed}
	ErrLimitExceeded       = &Error{Code: CodeLimitExceeded}
	ErrInvalidArgument     = &Error{Code: CodeInvalidArgument}
	ErrCapabilityMissing   = &Error{Code: CodeCapabilityMissing}
	ErrNoKeyring           = &Error{Code: CodeNoKeyring}
	ErrInsecurePermissions = &Error{Code: CodeInsecurePermissions}
	ErrBusy                = &Error{Code: CodeBusy}
	ErrBackend             = &Error{Code: CodeBackendError}
)

func fail(c Code, what string) error { return &Error{Code: c, What: what} }

// BackendError wraps an I/O or database error (backend_error).
func BackendError(what string, err error) error {
	return &Error{Code: CodeBackendError, What: what, Err: err}
}

// CodeOf is the result code of err: ok for nil, backend_error for an error that is not a
// store error.
func CodeOf(err error) Code {
	if err == nil {
		return CodeOK
	}
	var e *Error
	if asError(err, &e) {
		return e.Code
	}
	return CodeBackendError
}
