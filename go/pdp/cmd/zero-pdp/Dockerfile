FROM golang:1.26 AS build
ARG VERSION=dev
WORKDIR /src
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/pdp.Version=${VERSION}" \
	-o /out/zero-pdp ./pdp/cmd/zero-pdp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Binary in /app, config + secrets mounted at the WORKDIR /etc/pdp without shadowing the executable.
COPY --from=build /out/zero-pdp /app/zero-pdp
WORKDIR /etc/pdp
ENV PRETTY_LOGS=false
ENTRYPOINT ["/app/zero-pdp"]
