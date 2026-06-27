# zero-pdp

The authorization server (Policy Decision Point) of the [gematik Zero Trust Lab](https://github.com/gematik/zero-lab).
It runs the OAuth 2.0 authorization-code flow against the configured IdPs (direct OIDC, gematik
OpenID Federation / OIDF, or the gematik IDP-Dienst / gemidp), authenticates as a confidential client, and
issues **DPoP-bound** access tokens (RFC 9449) plus refresh + introspection (RFC 7662) for protected
resources. It is what the pep gateway acts as a client of.

`scratch` image, structured logs. Pairs with a Postgres kv store (sessions + nonces) or runs in-memory.

## Run

```sh
docker run -p 8011:8011 \
  -e DATABASE_URL='postgres://user:pass@db:5432/zero?sslmode=disable' \
  -v "$PWD/config:/etc/pdp:ro" \
  spilikin/zero-pdp:latest start
```

- Mount your config dir at **`/etc/pdp`** (the WORKDIR): `pdp.yaml` (domain config), `openid-providers.yaml`
  (the IdPs — shared flat format with pep), and the signing key (`sign.jwk`, referenced by `sign_jwk_path`).
- **Airgapped / test:** set `-e PDP_NON_PROD=true` and a `mock_idp` block in `pdp.yaml` — the PDP then issues a
  canned identity with no external OpenID Provider.
- Secrets are mounted files referenced by `*_PATH`, never baked in.

Full reference: [CONFIG.md](https://github.com/gematik/zero-lab/blob/main/go/pdp/cmd/zero-pdp/CONFIG.md).

| Var | For | Default |
| --- | --- | --- |
| `PDP_CONFIG_FILE` | the domain config file | `pdp.yaml` |
| `PDP_OPENID_PROVIDERS_PATH` | the IdPs file | `openid-providers.yaml` |
| `PDP_NON_PROD` | `true` → NonProdMode (mock IdP) | `false` |
| `DATABASE_URL` | Postgres kv store | in-memory |

## Tags

- `latest` — most recent build
- `X.Y.Z` — pinned, matching the `go/pdp/vX.Y.Z` source tag

## Source

https://github.com/gematik/zero-lab
