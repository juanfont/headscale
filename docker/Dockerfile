FROM golang:alpine

# Set necessary environmet variables needed for our image
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 



ENV PATH /usr/lib/postgresql/$PG_MAJOR/bin:$PATH
ENV PGDATA /var/lib/postgresql/data
ENV POSTGRES_DB headscale
ENV POSTGRES_USER admin

ENV LANG en_US.utf8

RUN apk update && \
    apk add git su-exec tzdata libpq postgresql-client postgresql postgresql-contrib gnupg supervisor inotify-tools wireguard-tools openssh && \
    mkdir /docker-entrypoint-initdb.d && \
    rm -rf /var/cache/apk/*

RUN gpg --keyserver ipv4.pool.sks-keyservers.net --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4
RUN gpg --list-keys --fingerprint --with-colons | sed -E -n -e 's/^fpr:::::::::([0-9A-F]+):$/\1:6:/p' | gpg --import-ownertrust
RUN wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/1.7/gosu-amd64" && \
    wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/1.7/gosu-amd64.asc" && \
    gpg --verify /usr/local/bin/gosu.asc && \
    rm /usr/local/bin/gosu.asc && \
    chmod +x /usr/local/bin/gosu
RUN apk --purge del gnupg ca-certificates

VOLUME /var/lib/postgresql/data




RUN rm -rf /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_dsa_key

WORKDIR /build

RUN git clone https://github.com/juanfont/headscale.git

WORKDIR /build/headscale

RUN go build cmd/headscale/headscale.go 

COPY headscale.sh /headscale.sh
COPY postgres.sh /postgres.sh
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /

RUN mkdir -p /run/postgresql
RUN chown postgres:postgres /run/postgresql

RUN adduser -S headscale

#ENV GIN_MODE release

EXPOSE 8000

CMD ["supervisord","--nodaemon", "--configuration", "/etc/supervisord.conf"]
