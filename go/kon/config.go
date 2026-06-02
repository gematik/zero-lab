package kon

// CredentialsConfig is an interface for different types of credentials
type CredentialsConfig interface{}

// CredentialsConfigBasic is a struct for HTTP basic credentials
type CredentialsConfigBasic struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// CredentialsConfigPKCS12 is a struct for PKCS#12 certificate credentials
type CredentialsConfigPKCS12 struct {
	Type     string `json:"type"`
	Data     string `json:"data"`
	Password string `json:"password,omitempty"`
}
