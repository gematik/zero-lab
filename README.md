# 🤝🔐 Experimenting with Zero Trust

## About The Project

> **Note:** This work is part of DSR PoC: https://dsr.gematik.solutions/.

> The Zero Trust model is a security concept based on the principle of maintaining strict access controls and not trusting anyone by default, even those already inside the network perimeter. It is a security framework that requires all users, both inside and outside the network perimeter, to be authenticated, authorized, and continuously validated for security configuration and posture before being granted or keeping access to applications and data.

zero-lab holds libraries and commands for experimenting with Zero Trust building blocks in the German Telematikinfrastruktur (TI), in two workspaces:

- [`go/`](./go): Go modules, each versioned by its own git tag `go/<module>/vX.Y.Z`, licensed under EUPL-1.2.
- [`rust/`](./rust): Rust crates, each versioned by its own git tag `rust/<crate>/vX.Y.Z`, licensed under EUPL-1.2.

| Workspace | Module | Purpose |
|---|---|---|
| Rust | [`ti-cli`](./rust/ti-cli) | `ti`, the command-line tool for the TI: PKI, identities, Konnektor, IDP-Dienst, FHIR-Directory |
| Rust | [`ti-pki`](./rust/ti-pki), [`ti-xmldsig`](./rust/ti-xmldsig), [`ti-report`](./rust/ti-report), [`ti-wasm`](./rust/ti-wasm) | Certificate and TSL validation against the TI PKI, also in the browser |
| Rust | [`ti-connector-client`](./rust/ti-connector-client), [`ti-idpd`](./rust/ti-idpd), [`ti-directory`](./rust/ti-directory) | Konnektor, IDP-Dienst and FHIR-Directory clients |
| Rust | [`jwz`](./rust/jwz), [`jwz-brainpool`](./rust/jwz-brainpool), [`ti-jwz`](./rust/ti-jwz), [`ti-pkcs12`](./rust/ti-pkcs12), [`ti-store`](./rust/ti-store), [`ti-types`](./rust/ti-types) | JOSE, brainpool, PKCS#12, caching and shared types |
| Go | [`epa`](./go/epa) | ePA client and the `zero-epa` command |
| Go | [`pdp`](./go/pdp), [`pep`](./go/pep), [`zaddy`](./go/zaddy) | Policy decision point (`zero-pdp`) and policy enforcement, including a Caddy-based PEP (`zero-caddy`) |
| Go | [`bff`](./go/bff) | OAuth/OIDC Backend-For-Frontend |
| Go | [`brainpool`](./go/brainpool), [`pkcs12`](./go/pkcs12) | Brainpool elliptic curves (RFC 5639) with X.509 and JOSE, PKCS#12 (RFC 7292) |
| Go | [`gemidp`](./go/gemidp), [`oauth`](./go/oauth), [`oidf`](./go/oidf), [`dpop`](./go/dpop), [`nonce`](./go/nonce), [`kv`](./go/kv) | IDP, OAuth, OpenID Federation, DPoP and supporting libraries |
| Go | [`metsubushi`](./go/metsubushi) | Pod smoke-test endpoint |

### Release Notes

See [ReleaseNotes.md](./ReleaseNotes.md) and [rust/ReleaseNotes.md](./rust/ReleaseNotes.md) for all information regarding the (newest) releases.

## Getting Started

### Prerequisites

- Go 1.26.4 or newer for the Go workspace
- Rust 1.96 or newer for the Rust workspace
- [just](https://github.com/casey/just) for the build, check and release recipes
- Docker for container builds (optional)

### Installation

Install the `ti` command-line tool from source:

```
git clone https://github.com/gematik/zero-lab.git
cd zero-lab/rust
just install
```

Go commands are installable directly from their module tags, for example:

```
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@latest
```

## Usage

```
ti --help
ti pki inspect card.pem
ti pki verify smcb.p12
```

For more examples or in-depth documentation, please refer to the READMEs of the individual modules, for example [`rust/ti-cli`](./rust/ti-cli/README.md), and to the development guides for [Go](./go/docs/development.md) and [Rust](./rust/docs/development.md). The design rules, conventions and language profiles are in [docs](./docs/README.md).

## Contributing

If you want to contribute, please check our [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

Copyright 2023-2026 gematik GmbH

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Parts of this software and - in isolated cases - content such as text or images may have been developed using the support of AI tools. They are subject to the same reviews, tests, and security checks as any other contribution. The functionality of the software itself is not based on AI decisions.

## Contact

We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes.
This software is currently being tested to ensure its technical quality and legal compliance. Your feedback is highly valued.
If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: [GitHub Issues](https://github.com/gematik/zero-lab/issues).
