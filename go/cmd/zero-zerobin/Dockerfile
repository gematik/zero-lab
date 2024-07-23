FROM golang:1.22 AS build

WORKDIR /src

# Download Go modules
COPY go.work go.work.sum ./

COPY cmd/zero-zerobin ./cmd/zero-zerobin 
COPY libzero ./libzero
COPY libvau ./libvau
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/zero-zerobin 

EXPOSE 8443

#FROM scratch
FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-zerobin /app/zero-zerobin
COPY --from=build /src/cmd/zero-zerobin/static /app/static

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-zerobin"]