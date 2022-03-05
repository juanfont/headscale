# Builder image
FROM docker.io/golang:1.17.8-bullseye AS build
ENV GOPATH /go
WORKDIR /go/src/headscale

COPY go.mod go.sum /go/src/headscale/
RUN go mod download

COPY . .

RUN GGO_ENABLED=0 GOOS=linux go install -a ./cmd/headscale
RUN strip /go/bin/headscale
RUN test -e /go/bin/headscale

# Production image
FROM gcr.io/distroless/base-debian11

COPY --from=build /go/bin/headscale /bin/headscale
ENV TZ UTC

EXPOSE 8080/tcp
CMD ["headscale"]
