FROM golang:1.11.2-alpine3.8
RUN apk update && apk add gcc libc-dev git libpcap-dev && rm -rf /var/cache/apk/*
WORKDIR /go/src/github.com/comcast/ravel
COPY .git $WORKDIR
COPY . $WORKDIR
RUN COMMIT=$(git rev-list -1 HEAD --) && \
    DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") && \
    VERSION=$(if [ -f .version ]; then cat .version; else echo -n 0.0.0; fi) && \
    go build -v -o ravel \
        -ldflags "-X main.commit=$COMMIT -X main.version=$VERSION -X main.buildDate=$DATE" \
        ./cmd/
ADD https://github.com/osrg/gobgp/releases/download/v2.8.0/gobgp_2.8.0_linux_amd64.tar.gz $WORKDIR/gobgp_2.8.0_linux_amd64.tar.gz
RUN tar xf $WORKDIR/gobgp_2.8.0_linux_amd64.tar.gz


FROM alpine:3.8
MAINTAINER RDEI Team <rdei@comcast.com>
RUN echo '@edgemain http://dl-3.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories
RUN apk update
RUN apk add libpcap
RUN apk add ipvsadm@edgemain
RUN apk add iptables
RUN apk add gcc
RUN apk add libc-dev
RUN apk add libpcap-dev
RUN apk add haproxy
RUN rm -rf /var/cache/apk/*

RUN touch /var/run/haproxy.pid

COPY --from=0 /go/src/github.com/Comcast/Ravel/ravel /bin/
COPY --from=0 /go/src/github.com/Comcast/Ravel/gobgp /bin/
COPY --from=0 /go/src/github.com/Comcast/Ravel/gobgpd /bin/
RUN chmod ugo+x /bin/gobgp
RUN ln -s /bin/ravel /bin/kube2ipvs

ENTRYPOINT ["/bin/ravel"]
