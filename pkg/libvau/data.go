package libvau

type Message1 struct {
	MessageType string
	ECDH_PK     ECDHData
	Kyber768_PK KEMData
}

type Message2 struct {
	MessageType string
	ECDH_ct     ECDHData
	Kyber768_ct []byte
	AEAD_ct     []byte
}

type Message3 struct {
	MessageType              string
	AEAD_ct                  []byte
	AEAD_ct_key_confirmation []byte
}

type Message3Inner struct {
	ECDH_ct     ECDHData
	Kyber768_ct []byte
	ERP         bool
	ESO         bool
}

type Message4 struct {
	MessageType              string
	AEAD_ct_key_confirmation []byte
}

type PublicVAUKeys struct {
	ECDH_PK     ECDHData
	Kyber768_PK KEMData
	IssuedAt    int64  `cbor:"iat"`
	ExpiresAt   int64  `cbor:"exp"`
	Commment    string `cbor:"comment"`
}

type SignedPublicVAUKeys struct {
	SignedPubKeys    *PublicVAUKeys `cbor:"-"`
	SignedPubKeysRaw []byte         `cbor:"signed_pub_keys"`
	Signature        []byte         `cbor:"signature-ES256"`
	CertHash         []byte         `cbor:"cert_hash"`
	Cdv              int            `cbor:"cdv"`
	OcspResponse     []byte         `cbor:"ocsp_response"`
}
