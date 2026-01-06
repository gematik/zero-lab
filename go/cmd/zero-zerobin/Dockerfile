FROM golang:1.22 AS build

RUN useradd -m -u 1000 zero
USER zero

WORKDIR /src

# Download Go modules
COPY go.work go.work.sum ./

COPY . /src

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/zero-zerobin 

EXPOSE 8443

#FROM scratch
FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-zerobin /app/zero-zerobin
COPY --from=build /src/cmd/zero-zerobin/static /app/static

USER 1000:1000

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-zerobin"]