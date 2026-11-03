# Build context: go/ (`just docker-build epa`). The image carries the Go client and the
# released Rust `ti` it drives: the SMC-B identity, the IDP-Dienst flow and the VAU certificate
# checks live there.

FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/epa.Version=${VERSION}" \
	./epa/cmd/zero-epa

FROM scratch
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-epa /app/zero-epa
# A static build, pinned by the hash in the release's SHA256SUMS.
ADD --checksum=sha256:4b67f09f9ddecabddaa423ae2136bb67e5810bcde5239cc5ea2e5ae578cfc8be --chmod=755 \
	https://github.com/gematik/zero-lab/releases/download/rust%2Fti-cli%2Fv0.5.0/ti-0.5.0-x86_64-unknown-linux-musl /app/ti
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
