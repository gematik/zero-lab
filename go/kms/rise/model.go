package rise

// Infomodell represents the information model of a Konnektor.
type Infomodell struct {
	Mandant      string `json:"Mandant"`
	Clientsystem string `json:"Clientsystem"`
	Workplace    string `json:"Workplace"`
}

// LoginRequest represents the request body for the login operation.
type LoginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}
