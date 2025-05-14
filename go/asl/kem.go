package asl

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

type KEMData []byte

func (kd KEMData) PublicKey() (kem.PublicKey, error) {
	return mlkem768.Scheme().UnmarshalBinaryPublicKey(kd)
}

// Encapsulate generates a shared secret and a ciphertext
func (kd KEMData) Encapsulate() (ss []byte, ct []byte, err error) {
	publicKey, err := kd.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	// Attention: ct and ss are not in the same order as in ECDHData.Encapsulate
	ct, ss, err = publicKey.Scheme().Encapsulate(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return ss, ct, nil
}

type KEMKeyPair struct {
	privateKey kem.PrivateKey
	PublicData KEMData
}

func GenerateKEMKeyPair(scheme kem.Scheme) (*KEMKeyPair, error) {
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	publicData, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &KEMKeyPair{
		privateKey: privateKey,
		PublicData: publicData,
	}, nil
}

func (kp *KEMKeyPair) Decapsulate(ciphertext []byte) ([]byte, error) {
	return kp.privateKey.Scheme().Decapsulate(kp.privateKey, ciphertext)
}
