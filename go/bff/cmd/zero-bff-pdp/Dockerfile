FROM golang:1.26 AS build

ARG VERSION=dev

WORKDIR /src

# Copy the whole go workspace so go.work resolves the pdp + bff modules.
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/zero-bff-pdp ./bff/cmd/zero-bff-pdp

# A passwd entry so the scratch image can run as a non-root user.
RUN echo 'pdpbff:x:65532:65532::/app:/sbin/nologin' > /out/passwd

# scratch — the lightest possible runtime (no distro, shell, or package manager).
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/passwd /etc/passwd
# Binary on PATH, config in the WORKDIR: mount your config + secrets at /app without shadowing the executable.
COPY --from=build /out/zero-bff-pdp /usr/local/bin/zero-bff-pdp

USER 65532:65532
WORKDIR /app
ENV PRETTY_LOGS=false
ENV PDP_CONFIG_PATH=/app/pdp.yaml
ENTRYPOINT ["/usr/local/bin/zero-bff-pdp"]
