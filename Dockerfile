FROM bufbuild/buf:1.0.0-rc6 as buf

FROM golang:1.17.1-bullseye AS build
ENV GOPATH /go

COPY --from=buf /usr/local/bin/buf /usr/local/bin/buf

COPY go.mod go.sum /go/src/headscale/
WORKDIR /go/src/headscale
RUN go mod download

COPY . .

RUN go install \
    github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
    github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
    google.golang.org/protobuf/cmd/protoc-gen-go \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc

RUN buf generate proto

RUN go install -a -ldflags="-extldflags=-static" -tags netgo,sqlite_omit_load_extension ./cmd/headscale
RUN test -e /go/bin/headscale

FROM ubuntu:20.04

RUN apt-get update \
    && apt-get install -y ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /go/bin/headscale /usr/local/bin/headscale
ENV TZ UTC

EXPOSE 8080/tcp
CMD ["headscale"]
