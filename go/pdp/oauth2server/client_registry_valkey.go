package oauth2server

import (
	"errors"

	"github.com/valkey-io/valkey-go"
)

type ValkeyClientRegistry struct {
	vk valkey.Client
}

func NewValkeyClientRegistry(option valkey.ClientOption) (ClientsRegistry, error) {
	vk, err := valkey.NewClient(option)
	if err != nil {
		return nil, err
	}
	return &ValkeyClientRegistry{vk: vk}, nil
}

func (r *ValkeyClientRegistry) GetClientMetadata(clientID string) (*ClientMetadata, error) {
	return nil, errors.New("not implemented")
}

func (r *ValkeyClientRegistry) RegisterClient(client *ClientMetadata) error {
	return errors.New("not implemented")
}
