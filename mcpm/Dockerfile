# Stage 1: Build headscale from source
FROM golang:1.26 AS builder
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN go build -buildmode=pie -ldflags "-X main.version=${VERSION}" -o headscale ./cmd/headscale

# Build genxid helper (generates unique xid for Litestream replica paths)
WORKDIR /genxid
COPY mcpm/genxid.go .
RUN go mod init genxid && go get github.com/rs/xid && go build -o genxid genxid.go

# Stage 2: Get litestream binary
FROM litestream/litestream:0.5.7 AS litestream

# Stage 3: Final image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/headscale /usr/local/bin/headscale
COPY --from=builder /genxid/genxid /usr/local/bin/genxid
COPY --from=litestream /usr/local/bin/litestream /usr/local/bin/litestream
COPY mcpm/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /var/lib/headscale /var/run/headscale /etc/headscale

EXPOSE 8080 9090 50443 3478/udp

ENTRYPOINT ["/entrypoint.sh"]
