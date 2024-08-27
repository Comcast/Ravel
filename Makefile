
# export  RAVEL_EARLYLATE=Y

#TAG=v2.6.0-proto205
TAG=v2.7.0-rc1
PROD=v2.7.6.3
SKIPMASTER=v2.6.1-skip-ipvsmaster

# branch: lab-isolated-later: original 2.6 + logging + skip-master
# branch: log-rules : original 2.6 +  early-late rules + logging

# v2.7.6.3: use go-1.20 - iproute2-6.6.0
# v2.7.6.2: add debug in sanitizeIPVSRule
# v2.7.6: remove --tun-type ipip
# v2.7.5: clean up '#' comments and --comments for ipvs-backend: ipvs-nfs-restore 
# v2.7.3: fix bug: skip invalid rules 
# v2.7.2 : add options to use env-var to select iptables-nft or iptables-legacy
# v2.7.1 : adding lock to getAllPods
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
# sudo systemctl daemon-reload; sudo systemctl restart ipvs-backend;  sudo journalctl -f -u ipvs-backend


default: build

test:
	go test github.com/Comcast/Ravel/pkg/system -run TestNewMerge -v


prod:
	docker build -t hub.comcast.net/k8s-eng/ravel:${PROD} -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:${PROD}

prod16:
	docker build -t hub.comcast.net/k8s-eng/ravel:${PROD}-1.6.2 -f Dockerfile-1.6.2 .
	docker push hub.comcast.net/k8s-eng/ravel:${PROD}-1.6.2

cc: FORCE
	docker build -t hub.comcast.net/k8s-eng/ravel:cc -f Dockerfile .
	#docker push hub.comcast.net/k8s-eng/ravel:cc
    



build: FORCE
	#docker build --progress plain -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
	docker build -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
	#docker push hub.comcast.net/k8s-eng/ravel:${TAG}


skipmaster:
	docker build --build-arg RAVEL_LOGRULE=N --build-arg SKIP_MASTER_NODE=Y -t hub.comcast.net/k8s-eng/ravel:${SKIPMASTER} -f Dockerfile .
	docker push hub.comcast.net/k8s-eng/ravel:${SKIPMASTER}



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


FORCE: ;
