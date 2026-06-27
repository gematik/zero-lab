FROM golang:1.26 AS build

ARG VERSION=dev

WORKDIR /src

# Copy the whole go workspace so go.work resolves the pep + provider modules.
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/pep.Version=${VERSION}" \
	-o /out/zero-pep-proxy ./pep/cmd/zero-pep-proxy

# A passwd entry so the scratch image can run as a non-root user.
RUN echo 'pep:x:65532:65532::/app:/sbin/nologin' > /out/passwd

# scratch — the lightest possible runtime (no distro, shell, or package manager).
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/zero-pep-proxy /app/zero-pep-proxy

USER 65532:65532
# Config + secrets dir (mount here). Separate from /app so it doesn't shadow the binary.
WORKDIR /etc/pep
ENV PRETTY_LOGS=false
ENTRYPOINT ["/app/zero-pep-proxy"]
