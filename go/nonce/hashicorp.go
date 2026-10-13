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

package nonce

import (
	"fmt"

	"github.com/hashicorp/go-secure-stdlib/nonceutil"
)

type HashicorpNonceService struct {
	nonceService nonceutil.NonceService
}

func NewHashicorpNonceService() (*HashicorpNonceService, error) {
	nonceService := nonceutil.NewNonceService()
	err := nonceService.Initialize()
	if err != nil {
		return nil, fmt.Errorf("could not initialize nonce service: %w", err)
	}
	return &HashicorpNonceService{nonceService}, nil
}

func (s *HashicorpNonceService) Get() (string, error) {
	nonceStr, _, err := s.nonceService.Get()
	if err != nil {
		return "", err
	}
	return nonceStr, nil
}

func (s *HashicorpNonceService) Redeem(nonceStr string) error {
	ok := s.nonceService.Redeem(nonceStr)
	if !ok {
		return fmt.Errorf("nonce %s not found", nonceStr)
	}
	return nil
}
