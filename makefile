TAG=v2.5.0-proto27

# Not a complicated makefile, just a place to ensure
# that we don't forget how to build and push to a registry.

default: build push

build:
	docker build -t hub.comcast.net/k8s-eng/ravel:${TAG} -f Dockerfile .

push:
	docker push hub.comcast.net/k8s-eng/ravel:${TAG}
