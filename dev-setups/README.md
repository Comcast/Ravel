## Dev-setups

This directory demonstrates how to setup a local development environment for the Ravel load balancer. It is intended for **linux** environment. Development on mac is a goal, but the path forward is not known due to evironment constraints. Primarily, `--net=host` is not implemented for Docker for Mac, meaning that communication from Ravel to Kubernetes is not possible (well, not easy).

 Diagram (TODO): 

- ravel as systemctl unit 
- send LVS rules on host machine set by ravel to IP address of minikube node
- create configmaps with local tooling. Perhaps static json file that permutes several critical functionalities of Ravel. Basically, it's our integration test

### Prerequisite tooling

- minikube 
- virtual box 
- docker 
- the Ravel repo