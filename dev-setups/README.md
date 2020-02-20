## Dev-setups

This directory demonstrates how to setup a local development environment for the Ravel load balancer. It is intended for **linux** environment. Development on Mac is a goal, but the path forward is not known due to evironment constraints. Primarily, you can't just up and run LVS on mac, and `--net=host` is not implemented for Docker for Mac, meaning that communication from Ravel to Kubernetes is not possible from a linux container running LVS to let the Director do it's thing.

 Diagram (TODO): 

- ravel running on host linux machine (or virtualbox VM). Binary, host-networked && privileged container, systemd, whatever
- send LVS rules on host machine set by ravel to IP address of minikube node
- configure minikube with a bunch of weird stuff
- run realserver on minikube as host-networked && privileged container. rkt on systemd is **not supported on minikube** as of this writing (2/20/20)
- create configmaps with local tooling. Perhaps static json file that permutes several critical functionalities of Ravel. Basically, it's our integration test

### Prerequisite tooling

- linux dev environment
- minikube 
- virtual box 
- docker 
- the Ravel repo