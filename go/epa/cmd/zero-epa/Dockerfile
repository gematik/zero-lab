FROM golang:1.26 AS build

ARG VERSION=dev

WORKDIR /src

# Copy Go source into builder
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/epa.Version=${VERSION}" \
	./epa/cmd/zero-epa

FROM scratch
#FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-epa /app/zero-epa

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-epa", "proxy"]
