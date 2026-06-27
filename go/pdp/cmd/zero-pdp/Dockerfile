FROM golang:1.26 AS build

ARG VERSION=dev

WORKDIR /src

# Copy Go source into builder
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/pdp.Version=${VERSION}" \
	./pdp/cmd/zero-pdp

FROM scratch
COPY --from=build /etc/ssl /etc/ssl
# Binary on PATH, config in the WORKDIR: mount your config + secrets at /app without shadowing the executable.
COPY --from=build /src/zero-pdp /usr/local/bin/zero-pdp

WORKDIR /app
ENV PRETTY_LOGS=false
ENTRYPOINT ["/usr/local/bin/zero-pdp"]
