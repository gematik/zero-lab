FROM golang:1.24 AS build

WORKDIR /src

# Copy Go source into builder
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./pdp/cmd/zero-pdp 

FROM scratch
#FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-epa /app/zero-pdp

WORKDIR /app
ENV PRETTY_LOGS=false
ENTRYPOINT ["/app/zero-pdp"]
