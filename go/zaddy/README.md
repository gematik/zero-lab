# Caddy based Zero Trust PEP (Zaddy)

## Development

```bash
go run ./cmd/zero-caddy run
```

```bash
curlie -k https://localhost:2019/
curlie -k https://localhost:2019/public
# This should fail
curlie -k https://localhost:2019/protected
```
