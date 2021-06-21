FROM golang:latest AS build
ENV GOPATH /go
COPY . /go/src/headscale
WORKDIR /go/src/headscale
RUN go install -a -ldflags="-extldflags=-static" -tags netgo,sqlite_omit_load_extension ./cmd/headscale
RUN test -e /go/bin/headscale

FROM scratch
COPY --from=build /go/bin/headscale /go/bin/headscale
ENV TZ UTC
EXPOSE 8080/tcp
ENTRYPOINT ["/go/bin/headscale"]
