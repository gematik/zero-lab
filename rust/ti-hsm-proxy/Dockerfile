# The production image of the HSM proxy sidecar (TASK-389, TASK-398). Build from rust/, the
# workspace:
#
#   docker build -f ti-hsm-proxy/Dockerfile -t hsm-proxy .
#
# The dynamically linked binary on distroless with the C runtime, the one exception to
# servers.md rule 4, because a PKCS#11 module is loaded with dlopen. It holds no module and has
# neither the simulator nor the conformance probes (rule 17): the vendor's module is mounted
# read-only and named by HSM_PROXY_PKCS11_MODULE_PATH and HSM_PROXY_PKCS11_MODULE_SHA256
# (rule 7). The simulator for development and tests is Dockerfile.simulator.

# rust:1.99.0-bookworm, the toolchain the workspace is checked with.
FROM rust@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
WORKDIR /src
COPY . ./
RUN cargo build --release --locked -p ti-hsm-proxy --bin hsm-proxy

# gcr.io/distroless/cc-debian12:nonroot: glibc, libgcc and libstdc++, no shell, user 65532.
FROM gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/hsm-proxy /hsm-proxy
ENTRYPOINT ["/hsm-proxy"]
