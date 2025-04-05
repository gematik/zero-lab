FROM golang:1.24 AS builder

WORKDIR /src

# Copy Go source into builder
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build ./zaddy/cmd/zero-caddy 

# based on https://github.com/caddyserver/caddy-docker/blob/master/2.9/alpine/Dockerfile
FROM alpine:3.20

RUN apk add --no-cache \
	ca-certificates \
	libcap \
	mailcap

RUN set -eux; \
	mkdir -p \
	/config/caddy \
	/data/caddy \
	/etc/caddy \
	/usr/share/caddy \
	; \
	wget -O /etc/caddy/Caddyfile "https://github.com/caddyserver/dist/raw/33ae08ff08d168572df2956ed14fbc4949880d94/config/Caddyfile"; \
	wget -O /usr/share/caddy/index.html "https://github.com/caddyserver/dist/raw/33ae08ff08d168572df2956ed14fbc4949880d94/welcome/index.html"

# https://github.com/caddyserver/caddy/releases
ENV CADDY_VERSION=v2.9.1

COPY --from=builder /src/zero-caddy /srv/zero-caddy
RUN addgroup -g 1000 -S caddy
RUN adduser -u 1000 -D -S -G caddy caddy
RUN chown caddy /srv/zero-caddy
RUN chmod 555 /srv/zero-caddy
RUN chown -R caddy:caddy /config /data
#RUN setcap 'cap_net_bind_service=+ep' /srv/zero-caddy

USER 1000

# See https://caddyserver.com/docs/conventions#file-locations for details
ENV XDG_CONFIG_HOME=/config
ENV XDG_DATA_HOME=/data

EXPOSE 80
EXPOSE 443
EXPOSE 443/udp
EXPOSE 2019

WORKDIR /srv

CMD ["/srv/zero-caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
