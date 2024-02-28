# Input for the application specific authorization hook

```json
{
    "traceId": "...", // Id of an authorization transaction, to be used to trace the logs across the system 
    "sessionId": "unique session Id", // will be used to Identify the access_token, e.g. as jti claim
    "authorizationScopes": ["scope1", "scope2"],
    "authorizationDetails": { 
        // see rfc9396
    },
    "subject": { // schemas/subject.yaml
        // claims from the Id token, esp. iss and iat
    },
    "client": { // schemas/client-authz-hook.yaml
        "name": "user or application chosen name",
        "clientId": "unique client instance Id",
        "productId": "product Identifier from gematik registration",
        "productVersion": "product version",
        "manufacturerId": "software product manufacturer Id",
        "owner": {
            "id": "owner Id",
            "authority": "gem-oidf|gem-idp|gem-pki",
            "type": "organization|indivIdual",
            "iss": "issuer of the owner Id, e.g. IDP Url"
        },
        "registrationTimestamp": 1234567890,
        "attestation": {
            "format": "apple-attestation|android-key-id-attestation|tmp2|none",
            "timestamp": 1234567890, // timestamp of the last attestation
        },
        "platform": "android|apple|software",
        "posture": { // "schemas/posture-xyz.yaml"
            // platform specific posture
            // see DSR Device Tokens
        }
    },
    "policyDecision": { // schemas/policy-decision.yaml
        "allow": true,
        "client": {
            "allow": true,
            "violations": []
        },
        "subject" {
            "allow": true,
            "violations": []
        },
        "security": {
            "allow": true,
            "violations": []
        },
        "sessionControl": {
            "subjectSeauthenticationPeriod": 24h,
            "clientAttestationPeriod": 6m,
            "maxSessionDuration": 24h,
        }
    }
}
```

Request information is only relevant for PEP and PDP 

```json
    "request": { // schemas/http-request.yaml
        "method": "GET",
        "headers": {
            "Accept": ["application/json", "text/plain", "*/*"],
            "Content-Type": ["application/json"],
            "User-Agent": ["xyz/0.21.1"]
        },
        "host": "api.example.com", // host:port
        "path": "/v1/endpoint",
        "query": {
            "foo": ["bar"] // array while multiple values possible
        },
        "scheme": "https",
        "fragment": "fragment",
        "tls": {
            "version": "TLSv1.2",
            "cipherSuite": "ECDHE-RSA-A",
            "clientCertificate": "base64encoded",
        },
        "dpop" {
            // rfc9449
        }
    },

```