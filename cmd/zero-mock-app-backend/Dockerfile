FROM golang:1.22 AS build

WORKDIR /src

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY pkg ./pkg

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/zero-mock-app-backend 

EXPOSE 8091

#FROM scratch
FROM ubuntu
COPY --from=build /src/zero-mock-app-backend /app/zero-mock-app-backend

WORKDIR /app
ENV PRETTY_LOGS=false
CMD ["/app/zero-mock-app-backend"]