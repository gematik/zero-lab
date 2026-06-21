FROM golang:1.26 AS build

WORKDIR /src

# Copy the whole go workspace so go.work resolves the pdp + bff modules.
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/pdp-bff ./bff/cmd/pdp-bff

FROM scratch
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /out/pdp-bff /app/pdp-bff

WORKDIR /app
ENV PRETTY_LOGS=false
ENV PDP_BFF_CONFIG=/config/pdp.yaml
ENTRYPOINT ["/app/pdp-bff"]
