FROM golang:1.15-alpine
RUN apk update && apk add gcc libc-dev git libpcap-dev && rm -rf /var/cache/apk/*
WORKDIR /app/src
COPY . /app/src
WORKDIR /app/src/cmd/ravel
RUN go build -v -o /app/src/cmd/ravel/ravel
#ADD https://github.com/osrg/gobgp/releases/download/v2.8.0/gobgp_2.8.0_linux_amd64.tar.gz gobgp_2.8.0_linux_amd64.tar.gz
#RUN tar xzf gobgp_2.8.0_linux_amd64.tar.gz
ADD https://github.com/osrg/gobgp/releases/download/v2.22.0/gobgp_2.22.0_linux_amd64.tar.gz gobgp_2.22.0_linux_amd64.tar.gz
RUN tar zxf gobgp_2.22.0_linux_amd64.tar.gz 
RUN ls -al


FROM alpine:3.8
LABEL MAINTAINER='RDEI Team <rdei@comcast.com>'
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

COPY --from=0 /app/src/cmd/ravel/ravel /bin/
COPY --from=0 /app/src/cmd/ravel/gobgp /bin/
COPY --from=0 /app/src/cmd/ravel/gobgpd /bin/
RUN chmod ugo+x /bin/gobgp
RUN ln -s /bin/ravel /bin/kube2ipvs

ENTRYPOINT ["/bin/ravel"]
