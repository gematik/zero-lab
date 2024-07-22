FROM golang:1.22 AS build

WORKDIR /src

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY pkg ./pkg
COPY templates ./templates
COPY static ./static

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/zero-zerobin 

EXPOSE 8443

#FROM scratch
FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-zerobin /app/zero-zerobin
COPY --from=build /src/templates /app/templates
COPY --from=build /src/static /app/static

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-zerobin"]