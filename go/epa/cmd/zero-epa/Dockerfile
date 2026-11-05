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
# A passwd entry and directories of their own, so the scratch image runs as a non-root user.
RUN echo 'epa:x:65532:65532::/var/lib/zero-epa:/sbin/nologin' > /etc/passwd.epa \
	&& mkdir -p /out/cache /out/home /out/tmp

FROM scratch
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /etc/passwd.epa /etc/passwd
COPY --from=build /src/zero-epa /app/zero-epa
# A static build, pinned by the hash in the release's SHA256SUMS.
ADD --checksum=sha256:4b67f09f9ddecabddaa423ae2136bb67e5810bcde5239cc5ea2e5ae578cfc8be --chmod=755 \
	https://github.com/gematik/zero-lab/releases/download/rust%2Fti-cli%2Fv0.5.0/ti-0.5.0-x86_64-unknown-linux-musl /app/ti
# ti needs a cache for the trust material, a home for its state and a temporary directory for
# the VAU checks, all writable by the user below. A volume mounted over the cache must be too:
# in Kubernetes, fsGroup 65532.
COPY --from=build --chown=65532:65532 /out/tmp /tmp
COPY --from=build --chown=65532:65532 /out/cache /var/cache/ti
COPY --from=build --chown=65532:65532 /out/home /var/lib/zero-epa
ENV EPA_TI_BIN=/app/ti
ENV TI_CACHE_DIR=/var/cache/ti
ENV TMPDIR=/tmp
ENV HOME=/var/lib/zero-epa
VOLUME /var/cache/ti

# An identity mounted from a Secret must be readable by this user (UID 65532).
USER 65532:65532
WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-epa", "proxy"]
