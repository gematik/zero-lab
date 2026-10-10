# Build context: the repository root (`just docker-build-epa`), since the image carries
# both the Go client and the Rust `ti` it drives.

# The ti tool, static for the scratch image: the SMC-B identity, the IDP-Dienst flow and
# the VAU certificate checks live there.
FROM rust:1.96-bookworm AS ti
ARG TI_TARGET=x86_64-unknown-linux-musl
RUN rustup target add ${TI_TARGET} && apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /src/rust
COPY rust/ ./
RUN cargo build --release --locked -p ti-cli --target ${TI_TARGET} \
	&& cp target/${TI_TARGET}/release/ti /ti

FROM golang:1.26 AS build
ARG VERSION=dev
WORKDIR /src
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/epa.Version=${VERSION}" \
	./epa/cmd/zero-epa

FROM scratch
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-epa /app/zero-epa
COPY --from=ti /ti /app/ti
# ti needs a cache for the trust material and a temporary directory for the VAU checks.
COPY --from=build --chown=0:0 /tmp /tmp
ENV EPA_TI_BIN=/app/ti
ENV TI_CACHE_DIR=/var/cache/ti
ENV TMPDIR=/tmp
ENV HOME=/app
VOLUME /var/cache/ti

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-epa", "proxy"]
