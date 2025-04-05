package nonce

type Options struct {
	ExpirySeconds int64
}

type Service interface {
	Get() (string, error)
	Redeem(nonceStr string) error
}
