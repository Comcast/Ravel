FROM golang:1.17-alpine

RUN echo '@edgemain http://dl-3.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories
RUN apk add bash libpcap iptables haproxy iproute2 ipvsadm@edgemain gcc libc-dev git libpcap-dev && rm -rf /var/cache/apk/*; rm -rf /var/cache/apk/*
