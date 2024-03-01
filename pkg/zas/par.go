package zas

import "github.com/gematik/zero-lab/pkg/util"

func GenerateRequestURI() string {
	return "urn:ietf:params:oauth:request_uri:" + util.GenerateRandomString(128)
}
