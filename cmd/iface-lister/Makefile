default:
	go build -v -o iface-lister
m1:
	docker buildx build --platform linux/amd64 --load -t hub.comcast.net/k8s-eng/iface-lister:unstable -f Dockerfile ../../
push:
	docker push hub.comcast.net/k8s-eng/iface-lister:unstable
