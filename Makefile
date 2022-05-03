TAG=v2.6.0-proto201

# v2.6.0-proto189 -> v2.6.0-rc4
# rc6: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto45
# rc7: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto66
# rc8: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto67
# rc9: hub.comcast.net/k8s-eng/ravel:v2.5.0-proto68

# Not a complicated makefile, just a place to ensure
# that we don't forget how to build and push to a registry.

default: build

build:
	#docker build --progress plain -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
	docker build -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .

push:
	#DOCKER_HOST=ssh://69.252.103.115 docker push hub.comcast.net/k8s-eng/ravel:${TAG}
	docker push hub.comcast.net/k8s-eng/ravel:${TAG}

default-gobgp: build-gobgp push-gobgp

build-gobgp:
	docker build -t hub.comcast.net/k8s-eng/gobgpd:v2.2.0 -f Dockerfile.gobgp .

push-gobgp:
	docker push hub.comcast.net/k8s-eng/gobgpd:v2.2.0

remote:
	DOCKER_HOST=ssh://69.252.103.115 docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .

m1:
	#DOCKER_HOST=ssh://69.252.103.115 docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
	docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .
