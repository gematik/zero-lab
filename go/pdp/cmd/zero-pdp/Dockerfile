FROM golang:1.24 AS build

WORKDIR /src

# Copy Go source into builder
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./pdp/cmd/zero-pdp 

RUN mkdir -p /etc/pdp

FROM scratch
#FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-pdp /app/zero-pdp
COPY --from=build /etc/pdp /etc/pdp


WORKDIR /app
ENV PRETTY_LOGS=false
ENV PDP_WORKDIR="/etc/pdp"
ENTRYPOINT ["/app/zero-pdp"]
