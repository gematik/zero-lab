package epa

import (
	"fmt"

	"github.com/gematik/zero-lab/go/epa"
)

// epaKeyPrefix is the ePA half of the shared state store; `pki:` is the other.
const epaKeyPrefix = "epa:"

// Key prefixes / constructors. Scope everything by env so dev/test/ref/prod
// don't collide.
func kvnrProviderKey(env epa.Env, kvnr string) string {
	return fmt.Sprintf("epa:provider-of:%s:%s", env, kvnr)
}

func vauKeysKey(env epa.Env, provider epa.ProviderNumber) string {
	return fmt.Sprintf("epa:vau-keys:%s:%d", env, provider)
}

func certPoolKey(env epa.Env) string {
	return fmt.Sprintf("epa:cert-pool:%s", env)
}
