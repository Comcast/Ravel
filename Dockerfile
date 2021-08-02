FROM golang:1.16-alpine
RUN apk update && apk add gcc libc-dev git libpcap-dev && rm -rf /var/cache/apk/*
WORKDIR /app/src
COPY . /app/src
WORKDIR /app/src/cmd/ravel
RUN go build -v -o /app/src/cmd/ravel/ravel
ADD https://github.com/osrg/gobgp/releases/download/v2.22.0/gobgp_2.22.0_linux_amd64.tar.gz gobgp_2.22.0_linux_amd64.tar.gz
RUN tar zxf gobgp_2.22.0_linux_amd64.tar.gz 
RUN ls -al


FROM alpine:3.8
LABEL MAINTAINER='RDEI Team <rdei@comcast.com>'
RUN echo '@edgemain http://dl-3.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories
RUN apk update
RUN apk add libpcap ipvsadm@edgemain iptables gcc libc-dev libpcap-dev haproxy iproute2
RUN rm -rf /var/cache/apk/*

COPY --from=0 /app/src/cmd/ravel/ravel /bin/
COPY --from=0 /app/src/cmd/ravel/gobgp /bin/
COPY --from=0 /app/src/cmd/ravel/gobgpd /bin/
RUN chmod 750 /bin/gobgp /bin/gobgpd /bin/ravel

ENTRYPOINT ["/bin/ravel"]
