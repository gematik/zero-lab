package oauth2client_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/oauth/oauth2client"
	"golang.org/x/oauth2"
)

func TestOAuth2Client(t *testing.T) {
	client := &oauth2.Config{
		ClientID:    "public-client",
		RedirectURL: "http://127.0.0.1:8089/as-callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://127.0.0.1:8011/auth",
			TokenURL: "http://127.0.0.1:8011/token",
		},
	}

	verifier := oauth2.GenerateVerifier()
	authURL := client.AuthCodeURL("state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("scope", "zero"))
	t.Log(authURL)

	callbackChan := oauth2client.StartCallbackServer("127.0.0.1:8089", "/as-callback", 60*time.Second)
	t.Log("Started callback server")

	cmd := exec.Command("open", authURL)
	_, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to run command: %v", err)
	}

	callback := <-callbackChan
	if callback.Error != nil {
		t.Fatal(callback.Error)
	}

	t.Log("Got callback", callback)

	token, err := client.Exchange(context.Background(), callback.Code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Got token", token)
}
