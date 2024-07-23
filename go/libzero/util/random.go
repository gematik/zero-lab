package util

import (
	"crypto/rand"
	"math/big"
)

func GenerateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic("Random number generation failed")
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}
