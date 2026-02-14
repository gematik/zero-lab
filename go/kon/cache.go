package kon

// Cache is an optional key-value store for caching SOAP responses.
// Implementations decide persistence, eviction, and storage format.
type Cache interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte)
}
