FROM golang:latest AS build
ENV GOPATH /go

COPY go.mod go.sum /go/src/headscale/
WORKDIR /go/src/headscale
RUN go mod download

COPY . /go/src/headscale

RUN go install -a -ldflags="-extldflags=-static" -tags netgo,sqlite_omit_load_extension ./cmd/headscale
RUN test -e /go/bin/headscale

FROM ubuntu:latest

COPY --from=build /go/bin/headscale /usr/local/bin/headscale
ENV TZ UTC

EXPOSE 8080/tcp
CMD ["headscale"]
