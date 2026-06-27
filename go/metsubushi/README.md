# metsubushi

A featherweight pod **smoke-test** endpoint, styled after the
[gematik developer portal](https://developer.gematik.solutions). It serves a
responsive HTML page that reports live pod information and reflects request
headers back to you, plus a small [httpbin](https://httpbin.org)-style JSON API.

The whole thing is a single static Go binary embedded into a `scratch` image —
**~8.5 MB**, no shell, no libc, runs as a **non-root** user on port **8080**.

## Endpoints

| Method | Path                | Description                              |
| ------ | ------------------- | ---------------------------------------- |
| GET    | `/`                 | The HTML smoke-test page                 |
| GET    | `/healthz`          | Liveness, uptime, request count          |
| GET    | `/api/info`         | Pod metadata (hostname, pod name/IP, …)  |
| GET    | `/api/headers`      | Reflected request headers                |
| GET    | `/api/get`          | Echo: method, args, headers, origin      |
| GET    | `/api/anything`     | Alias of `/api/get`                      |
| GET    | `/api/ip`           | Client origin IP                         |
| GET    | `/api/uuid`         | Random UUIDv4                            |
| GET    | `/api/status/{code}`| Returns the given HTTP status code       |

## ZETA PEP proxy headers

When the page is served behind the gematik ZETA PEP HTTP Proxy
(A_25669-01), the proxy injects three additional headers carrying
**Base64-URL-encoded JSON**. The page detects them, decodes the payload, and
renders it as syntax-highlighted JSON (the raw value stays available behind a
*raw base64url* toggle):

| Header                     | Contents                          |
| -------------------------- | --------------------------------- |
| `zeta-user-info`           | User-Info structure               |
| `zeta-popp-token-content`  | PoPP token payload                |
| `zeta-client-data`         | Client data                       |

## Run

```bash
docker build -t metsubushi:latest .
docker run --rm -p 8080:8080 metsubushi:latest
# open http://localhost:8080
```

Surface real pod identity via environment variables (the Kubernetes manifest
wires these up through the downward API):

```bash
docker run --rm -p 8080:8080 \
  -e POD_NAME=metsubushi-7c9f-abcde \
  -e POD_NAMESPACE=default \
  -e POD_IP=10.42.1.7 \
  -e NODE_NAME=node-eu-2 \
  metsubushi:latest
```

| Variable        | Purpose                                  |
| --------------- | ---------------------------------------- |
| `PORT`          | Listen port (default `8080`)             |
| `POD_NAME`      | Pod name shown on the page               |
| `POD_NAMESPACE` | Namespace shown on the page              |
| `POD_IP`        | Pod IP shown on the page                 |
| `NODE_NAME`     | Node name shown on the page              |
| `SERVICE_NAME`  | Service label (default `metsubushi`)     |
| `LOGOUT_URL`    | If set, shows a **Log out** button that navigates here |

## Kubernetes

```bash
kubectl apply -f k8s.yaml
```

The manifest runs the pod non-root with a read-only root filesystem, all
capabilities dropped, and liveness/readiness probes on `/healthz`.

## Local development

No external dependencies — `index.html` is embedded into the binary at build
time via `go:embed`.

```bash
go run .          # serves on :8080
go vet ./...
```
