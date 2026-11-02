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

// Package nonce issues single-use replay nonces.
package nonce

// Options holds a nonce lifetime, ExpirySeconds, in seconds. The services in this package do not read it:
// NewKVService takes its lifetime as an argument.
type Options struct {
	ExpirySeconds int64
}

// Service issues replay nonces and redeems them. Redeem fails for a nonce that is unknown, expired or
// already redeemed, so each nonce is accepted at most once.
type Service interface {
	Get() (string, error)
	Redeem(nonceStr string) error
}
