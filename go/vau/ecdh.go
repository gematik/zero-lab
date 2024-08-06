package vau

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type ECDHData struct {
	Crv string `cbor:"crv"`
	X   []byte `cbor:"x"`
	Y   []byte `cbor:"y"`
}

func (ed *ECDHData) PublicKey() (*ecdh.PublicKey, error) {
	ecdsaPublicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(ed.X),
		Y:     new(big.Int).SetBytes(ed.Y),
	}

	ecdhPublicKey, err := ecdsaPublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("parsing ECDH public key: %w", err)
	}

	return ecdhPublicKey, nil
}

func (ed *ECDHData) Encapsulate() (ss []byte, ct *ECDHData, err error) {
	puk, err := ed.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("decoding ECDH public key: %w", err)
	}

	ecdsaPrK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating EC key pair: %w", err)
	}

	ecdhPrK, err := ecdsaPrK.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("generating ECDH key pair: %w", err)
	}

	ss, err = ecdhPrK.ECDH(puk)
	if err != nil {
		return nil, nil, fmt.Errorf("computing shared key: %w", err)
	}

	return ss, &ECDHData{
		Crv: ed.Crv,
		X:   ecdsaPrK.X.Bytes(),
		Y:   ecdsaPrK.Y.Bytes(),
	}, nil
}

type ECKeyPair struct {
	privateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
	PublicData ECDHData
}

// GenerateRandomECKeyPair generates a random EC key pair
func GenerateRandomECKeyPair(curve elliptic.Curve) (*ECKeyPair, error) {
	ecdsaPrK, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating EC key pair: %w", err)
	}

	ecdhPrK, err := ecdsaPrK.ECDH()
	if err != nil {
		return nil, fmt.Errorf("generating ECDH key pair: %w", err)
	}

	return &ECKeyPair{
		privateKey: ecdhPrK,
		PublicKey:  ecdhPrK.PublicKey(),
		PublicData: ECDHData{
			Crv: curve.Params().Name,
			X:   ecdsaPrK.X.Bytes(),
			Y:   ecdsaPrK.Y.Bytes(),
		},
	}, nil
}

// Decapsulate computes the shared secret between the private key and the public key of the sender
func (kp *ECKeyPair) Decapsulate(ecdhData *ECDHData) (ss []byte, err error) {
	ecc_public_key_sender, err := ecdhData.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("decoding ECDH public key: %w", err)
	}
	return kp.privateKey.ECDH(ecc_public_key_sender)
}
