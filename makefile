# Not a complicated makefile, just a place to ensure
# that we don't forget how to build and push to a registry.
all: 
	go build github.com/Comcast/Ravel/cmd

container:
	GOOS=linux GOARCH="amd64" go build github.com/comcast/ravel

docker: Dockerfile
	docker build -t kube2ipvs .
	N=`cat buildno`; M=$$(/bin/expr $$N + 1);echo $$M > buildno

push:
	docker tag kube2ipvs:latest registry.vipertv.net/viper/ravel:2.3.7
	docker push registry.vipertv.net/viper/ravel:2.3.7

push2:
	docker tag kube2ipvs:latest hub.comcast.net/viper/ravel:2.3.7
	docker push hub.comcast.net/viper/ravel:2.3.7
