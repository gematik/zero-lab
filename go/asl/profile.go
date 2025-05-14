package asl

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

type Profile struct {
	KemScheme     kem.Scheme
	HeaderNameCid string
	ChannelPath   string
	CertDataPath  string
}

var ProfileZetaAsl = Profile{
	KemScheme:     mlkem768.Scheme(),
	HeaderNameCid: "ZETA-ASL-CID",
	ChannelPath:   "/ASL",
}
