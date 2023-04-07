# Builder image
FROM docker.io/golang:1.20-bullseye AS build
ARG VERSION=dev
ENV GOPATH /go
WORKDIR /go/src/headscale

COPY go.mod go.sum /go/src/headscale/
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go install -tags ts2019 -ldflags="-s -w -X github.com/juanfont/headscale/cmd/headscale/cli.Version=$VERSION" -a ./cmd/headscale
RUN strip /go/bin/headscale
RUN test -e /go/bin/headscale

# Production image
FROM gcr.io/distroless/base-debian11

COPY --from=build /go/bin/headscale /bin/headscale
ENV TZ UTC

EXPOSE 8080/tcp
CMD ["headscale"]
