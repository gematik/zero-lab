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
