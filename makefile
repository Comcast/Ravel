# Not a complicated makefile, just a place to ensure
# that we don't forget how to build and push to a registry.

default: build push

build:
	docker build -t hub.comcast.net/viper/ravel:2.5.0-proto1 -f Dockerfile .

push:
	docker push hub.comcast.net/viper/ravel:2.5.0-proto1
