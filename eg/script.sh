#!/bin/sh
VERSION=$1

grep -v CONTAINER_IPVS /etc/environment > /etc/environment.new
grep -v CONTAINER_RAVEL /etc/environment.new > /etc/environment

cat << EOF >> /etc/environment
CONTAINER_IPVS=docker://hub.comcast.net/k8s-eng/ravel:$VERSION
CONTAINER_RAVEL=docker://hub.comcast.net/k8s-eng/ravel:$VERSION
CONTAINER_RAVEL_DIRECTOR=docker://hub.comcast.net/k8s-eng/ravel:$VERSION
EOF

cat /etc/environment | grep ravel
systemctl restart ipvs-backend
