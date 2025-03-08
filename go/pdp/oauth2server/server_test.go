package oauth2server

func createTestAuthzServer() (*Server, error) {
	return New(Config{})
}
