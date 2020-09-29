# Not a complicated makefile, just a place to ensure
# that we don't forget how to build and push to a registry.
all: 
	go build -o ravel -v ./cmd/

linux:
	GOOS=linux GOARCH="amd64" go build -o ravel -v ./cmd/

# this needs some TLC. It doesn't correspond to any notion of semver,
# so it's not very useful unless you are testing a local build 
docker: 
	docker build . -t  ravel-dev:0.0.1