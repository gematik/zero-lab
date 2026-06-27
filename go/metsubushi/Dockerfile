FROM golang:1.26 AS build

ARG VERSION=dev

WORKDIR /src

# Copy the whole go workspace so go.work resolves the metsubushi module.
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/metsubushi ./metsubushi

# A passwd entry so the scratch image can run as a non-root user.
RUN echo 'metsubushi:x:65532:65532::/app:/sbin/nologin' > /out/passwd

# scratch — the lightest possible runtime (no distro, shell, or package manager).
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/metsubushi /usr/local/bin/metsubushi

USER 65532:65532
WORKDIR /app
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/usr/local/bin/metsubushi"]
