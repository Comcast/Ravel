#TAG=v2.6.0-proto205
TAG=v2.6.0-cc20
SKIPMASTER=v2.6.1-skip-ipvsmaster

# branch: lab-isolated-later: original 2.6 + logging + skip-master
# branch: log-rules : original 2.6 +  early-late rules + logging

# v2.7: iptable version, skip-master, order-rules, group rules, reverse default for ipvs-ignore-node-cordon
# v2.6.1-skip-ipvsmaster : skip-ipvs-master based on env-var. use iptables 1.6.2
# hub.comcast.net/k8s-eng/ravel:v2.6.0-proto205 -> v2.6.0-rc7
# v2.6.0-proto189 -> v2.6.0-rc4
# rc6: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto45
# rc7: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto66
# rc8: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto67
# rc9: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto68

# Not a complicated makefile, just a place to ensure
# that we don't forget how to build and push to a registry.
#


default: build

test:
	go test github.com/Comcast/Ravel/pkg/system -run TestNewMerge -v

FORCE: ;

cc: FORCE
	docker build -t hub.comcast.net/k8s-eng/ravel:cc -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:cc
	

build:
	#docker build --progress plain -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
	docker build -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .

push:
	#DOCKER_HOST=ssh://69.252.103.115 docker push hub.comcast.net/k8s-eng/ravel:${TAG}
	docker push hub.comcast.net/k8s-eng/ravel:${TAG}

skipmaster:
	docker build --build-arg RAVEL_LOGRULE=N --build-arg SKIP_MASTER_NODE=Y -t hub.comcast.net/k8s-eng/ravel:${SKIPMASTER} -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:${SKIPMASTER}

# ipvsadm.c restore (-R) : ignore return code
rc1: FORCE
	docker build --build-arg RAVEL_LOGRULE=N --build-arg SKIP_MASTER_NODE=N -t hub.comcast.net/k8s-eng/ravel:2.6.2-rc1 -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:2.6.2-rc1

# ip.go : fix the Compare, comvert _ to .
rc4: FORCE
	docker build --build-arg RAVEL_LOGRULE=N --build-arg SKIP_MASTER_NODE=N -t hub.comcast.net/k8s-eng/ravel:2.6.2-rc4 -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:2.6.2-rc4

# both fixes
rc5: FORCE
	docker build --build-arg RAVEL_LOGRULE=N --build-arg SKIP_MASTER_NODE=N -t hub.comcast.net/k8s-eng/ravel:2.6.2-rc5 -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:2.6.2-rc5



default-gobgp: build-gobgp push-gobgp

build-gobgp:
	docker build -t hub.comcast.net/k8s-eng/gobgpd:v2.2.0 -f Dockerfile.gobgp .

push-gobgp:
	docker push hub.comcast.net/k8s-eng/gobgpd:v2.2.0

remote:
	DOCKER_HOST=ssh://69.252.103.115 docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .

m1:
	DOCKER_HOST=ssh://69.252.103.115 docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
	#docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
