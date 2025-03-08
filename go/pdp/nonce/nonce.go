package nonce

type Stats struct {
	Active int
}

type Service interface {
	Get() (string, error)
	Redeem(nonceStr string) error
	Stats() (*Stats, error)
}
