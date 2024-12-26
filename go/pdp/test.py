import requests
import secrets
import hashlib
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading

as_url = "http://127.0.0.1:8011"

# load the metadata
metadata_url = as_url + "/.well-known/oauth-authorization-server"
metadata = requests.get(metadata_url).json()


print(metadata)

# load available openid providers
providers_url = metadata["openid_providers_endpoint"]

providers = requests.get(providers_url).json()
print(providers)

op_issuer = providers[1]["iss"]

authorization_endpoint = metadata["authorization_endpoint"]

code_verifier = secrets.token_urlsafe(48)

# code challenge
code_challenge = (
    base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
    .decode()
    .replace("=", "")
)

# code challenge method
code_challenge_method = "S256"

# nonce
nonce = secrets.token_urlsafe(48)

# state
state = secrets.token_urlsafe(48)

client_id = "public-client"

# prepare the request
params = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": "http://127.0.0.1:8089/as-callback",
    "scope": "zero",
    "code_challenge": code_challenge,
    "code_challenge_method": code_challenge_method,
    "nonce": nonce,
    "state": state,
    "op_issuer": op_issuer,
}

# send the request
response = requests.get(authorization_endpoint, params=params, allow_redirects=False)

if response.status_code != 302:
    print("Error: Unexpected response from the authorization server.")
    print(response.text)
    exit()

# get redirect location
redirect_location = response.headers["Location"]

print(redirect_location)


# Global flag to stop the server once the code is received
received_code = False
auth_code = None


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global received_code
        # Parse the URL and path
        parsed_path = urlparse(self.path)

        # Check if the path matches '/as-callback'
        if parsed_path.path == "/as-callback":
            # Parse query parameters
            query_components = parse_qs(parsed_path.query)

            # Check if we received an authorization code
            auth_code = query_components.get("code", [""])[0]
            error = query_components.get("error", [""])[0]

            if auth_code:
                # Log the authorization code (for demonstration purposes)
                token_endpoint = metadata["token_endpoint"]
                token_params = {
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "client_id": client_id,
                    "redirect_uri": "http://127.0.0.1:8089/as-callback",
                    "code_verifier": code_verifier,
                }
                token_response = requests.post(token_endpoint, data=token_params)
                print(token_response.json())

                access_token = token_response.json()["access_token"]
                access_token_claims = base64.urlsafe_b64decode(
                    access_token.split(".")[1] + "==="
                )

                print(access_token_claims)

                # Send success response
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Authorization Code Received!</h1><ul><li>%s</li><li>%s</li></ul></body></html>"
                    % (access_token.encode(), access_token_claims)
                )

                # Stop the server once the code is received
                received_code = True
                threading.Thread(target=httpd.shutdown).start()
            elif error:
                # Handle OAuth errors (e.g., user denied authorization)
                print(f"Error: {error}")

                # Send error response
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Error during authorization</h1><p>Reason: %s</p></body></html>"
                    % error.encode()
                )
            else:
                # Handle cases where no code or error is provided
                print("No authorization code or error received.")

                # Send error response
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Invalid Request</h1><p>No code or error provided.</p></body></html>"
                )
        else:
            # If the path is not '/as-callback', return 404
            self.send_response(404)
            self.end_headers()


# Define the server address and port
server_address = ("", 8089)

# Create the HTTP server
httpd = HTTPServer(server_address, OAuthCallbackHandler)

# Start the server in a separate thread to allow it to be stopped
print("Starting server on port 8089...")
server_thread = threading.Thread(target=httpd.serve_forever)
server_thread.start()
