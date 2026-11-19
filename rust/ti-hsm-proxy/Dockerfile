# The HSM proxy sidecar (TASK-389, TASK-398). Build from rust/, the workspace:
#
#   docker build -f ti-hsm-proxy/Dockerfile --target hsm-proxy -t hsm-proxy .
#   docker build -f ti-hsm-proxy/Dockerfile --target hsm-proxy-simulator -t hsm-proxy-simulator .
#
# hsm-proxy is the production image: the dynamically linked binary on distroless with the C
# runtime, the one exception to servers.md rule 4, because a PKCS#11 module is loaded with
# dlopen. It holds no module; the vendor's is mounted read-only and named by
# HSM_PROXY_PKCS11_MODULE_PATH and HSM_PROXY_PKCS11_MODULE_SHA256 (rule 7).
#
# hsm-proxy-simulator is for development and tests only: the binary with the feature simulator
# and SoftHSM2 2.7.0 built from source (decision-17) against bookworm's OpenSSL, whose
# libcrypto distroless/cc holds. Debian bookworm's softhsm2 is 2.6.1, which lacks
# CKM_ECDSA_SHA256.

# rust:1.99.0-bookworm, the toolchain the workspace is checked with.
FROM rust@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
WORKDIR /src
COPY . ./
RUN cargo build --release --locked -p ti-hsm-proxy --bin hsm-proxy \
 && cp target/release/hsm-proxy /hsm-proxy \
 && cargo build --release --locked -p ti-hsm-proxy --bin hsm-proxy --features simulator \
 && cp target/release/hsm-proxy /hsm-proxy-simulator

FROM rust@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS softhsm
ARG SOFTHSM_VERSION=2.7.0
# The tag archive of github.com/softhsm/SoftHSMv2, as Homebrew's formula pins it.
ARG SOFTHSM_SHA256=be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /softhsm
RUN curl -fsSL -o softhsm.tar.gz \
      "https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz" \
 && echo "${SOFTHSM_SHA256}  softhsm.tar.gz" | sha256sum -c - \
 && tar xzf softhsm.tar.gz --strip-components 1 \
 && cmake -B build -DCMAKE_BUILD_TYPE=Release -DWITH_CRYPTO_BACKEND=openssl -DENABLE_GOST=OFF \
      -DDISABLE_NON_PAGED_MEMORY=ON -DBUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=/opt/softhsm \
 && cmake --build build -j"$(nproc)" \
 && cmake --install build \
 && mkdir -p /out/lib \
 && cp /opt/softhsm/lib/softhsm/libsofthsm2.so /out/lib/ \
 && printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' > /out/softhsm2.conf

# gcr.io/distroless/cc-debian12:nonroot: glibc, libgcc and libstdc++, no shell, user 65532.
FROM gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS hsm-proxy
COPY --from=build /hsm-proxy /hsm-proxy
ENTRYPOINT ["/hsm-proxy"]

FROM gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS hsm-proxy-simulator
COPY --from=build /hsm-proxy-simulator /hsm-proxy
COPY --from=softhsm /out/lib/ /opt/softhsm/lib/
COPY --from=softhsm /out/softhsm2.conf /etc/softhsm2.conf
# The token directory and the socket are the paths it writes (rule 27): mount an emptyDir or a
# tmpfs over /var/lib/softhsm/tokens and the socket's directory.
ENV SOFTHSM2_CONF=/etc/softhsm2.conf \
    HSM_PROXY_SIMULATOR=true \
    HSM_PROXY_PKCS11_MODULE_PATH=/opt/softhsm/lib/libsofthsm2.so
ENTRYPOINT ["/hsm-proxy"]
