# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# Build is dependency-free; copy the source straight in.
COPY go.mod ./
COPY main.go index.html ./

# Static, stripped, reproducible binary. CGO off so it runs on scratch.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /metsubushi .

# ---- runtime stage ----
FROM scratch
COPY --from=build /metsubushi /metsubushi

# Run as a non-root, non-existent UID; scratch has no users to map.
USER 65532:65532
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/metsubushi"]
