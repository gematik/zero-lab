FROM golang:1.25 AS build

WORKDIR /src

# Copy Go source into builder
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./epa/cmd/zero-epa 

FROM scratch
#FROM ubuntu
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /src/zero-epa /app/zero-epa

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-epa", "proxy"]
