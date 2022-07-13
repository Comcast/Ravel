FROM golang:1.17-alpine
RUN echo '@edgemain http://dl-3.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories
RUN apk add libpcap iptables haproxy iproute2 ipvsadm@edgemain gcc libc-dev git libpcap-dev && rm -rf /var/cache/apk/*
WORKDIR /app/src
COPY . /app/src
WORKDIR /app/src/cmd/ravel
RUN CGO_ENABLED=1 go build -v -o /app/src/cmd/ravel/ravel
ADD https://github.com/osrg/gobgp/releases/download/v2.22.0/gobgp_2.22.0_linux_amd64.tar.gz gobgp_2.22.0_linux_amd64.tar.gz
RUN tar zxf gobgp_2.22.0_linux_amd64.tar.gz 
RUN ls -al


# alpine:3.8 uses iptables v1.6.2
# golang:1.17-alpine uses iptables v1.8.8

# FROM alpine:3.8
FROM golang:1.17-alpine

ARG SKIP_MASTER_NODE=N
ARG RAVEL_LOGRULE=N
ARG RAVEL_EARLYLATE=Y
ENV SKIP_MASTER_NODE=$SKIP_MASTER_NODE
ENV RAVEL_LOGRULE=$RAVEL_LOGRULE
ENV RAVEL_EARLYLATE=$RAVEL_EARLYLATE

LABEL MAINTAINER='RDEI Team <rdei@comcast.com>'

RUN echo '@edgemain http://dl-3.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories
RUN apk add bash libpcap iptables haproxy iproute2 ipvsadm@edgemain gcc libc-dev git libpcap-dev && rm -rf /var/cache/apk/*; rm -rf /var/cache/apk/*
COPY --from=0 /app/src/cmd/ravel/ravel /bin/
COPY --from=0 /app/src/cmd/ravel/ravel /bin/kube2ipvs
COPY --from=0 /app/src/cmd/ravel/gobgp /bin/
COPY --from=0 /app/src/cmd/ravel/gobgpd /bin/
RUN chmod 750 /bin/gobgp /bin/gobgpd /bin/ravel
ENTRYPOINT ["/bin/ravel"]
