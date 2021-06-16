#!/bin/sh

VERSION=v2.5.0-proto42
USERNAME=core

# Example entries in /etc/environment that need updating
#CONTAINER_IPVS=docker://hub.comcast.net/k8s-eng/ravel:v2.5.1-proto38
#CONTAINER_RAVEL=docker://hub.comcast.net/k8s-eng/ravel:v2.5.1-proto38
#CONTAINER_RAVEL_DIRECTOR=docker://hub.comcast.net/k8s-eng/ravel:v2.5.1-proto38


# loop over servers and add the new env var to all nodes, then bounce the ipvs-backend service
# to make this easy, we just drop it at the end of the /etc/environment file
for server in `cat server-list.txt`; do
	echo "---> $server"
	scp -o ConnectTimeout=4 script.sh $USERNAME@$server:
	ssh -o ConnectTimeout=4 $USERNAME@$server <<< "sudo bash ./script.sh $VERSION"
	echo ""
done
