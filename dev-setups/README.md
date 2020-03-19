## Dev-setups

This directory demonstrates how to setup a local development environment for the Ravel load balancer. It is intended for **linux** environment. Development on Mac is a goal, but the path forward is not known due to evironment constraints. Primarily, you don't have the `ipvsadm` binary available, and `net=host` for docker is not supported on mac, so you can't build a container and run it there.

 Diagram (TODO): 

### Prerequisite tooling

- linux dev environment
- [minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
- [virtual box](https://websiteforstudents.com/installing-virtualbox-5-2-ubuntu-17-04-17-10/)
- [docker]
- the Ravel repo
- [golang](https://golang.org/doc/install)
- gobgp: `sudo apt-get update -y && sudo apt-get install gobgp`
- gobgpd: `sudo apt-get update -y && sudo apt-get install gobgpd`
   
0. start your cluster with an appropriate version

`minikube start  --kubernetes-version=v1.12.7 --vm-driver=virtualbox`

1. Add the kubeconfig for minikube to /etc/kubernetes
 
**NOTE: The password for the docker user in minikube is ** `tcuser`

```
cp ~/.kube/config .
sed -i "s/$USER/docker/g" config
scp -r $(minikube ssh-key) config docker@$(minikube ip):/home/docker/
ssh docker@$(minikube ip) 'sudo mv /home/docker/config /etc/kubernetes/kubeconfig'
```

3. Mount the minikube cert bundle, so your kubeconfig works

```
ssh docker@$(minikube ip) 'mkdir ~/.minikube'
scp -r $(minikube ssh-key) ~/.minikube/*.pem docker@$(minikube ip):.minikube/
scp -r $(minikube ssh-key) ~/.minikube/*.crt docker@$(minikube ip):.minikube/
scp -r $(minikube ssh-key) ~/.minikube/*.key docker@$(minikube ip):.minikube/
```

4. Create the netconf directory

```
scp -r $(minikube ssh-key) netconf docker@$(minikube ip):/home/docker/
ssh docker@$(minikube ip) 'sudo mv /home/docker/netconf /'
```

4. create the configmap

```
kubectl create ns platform-load-balancer
kubectl create -f minikube-configmap.yml
```  

5. create the daemonset

`kubectl create -f ./deployments/realserver/realserver.yaml`

6. Create the test server and service

```
kubectl create -f ./deployments/quote-server/quote-server.yaml
kubectl create -f ./deployments/quote-server/quote-server-service.yaml
```

7. Create the configmap, configured to look at the test server:

```
kubectl create ns platform-load-balancer
kubectl create -f minikube-configmap.yml
```

8. Run `gobgpd`:

`sudo gobgpd -f bgp-configuration/gobgp.conf`

Note: The IP address shown may not be the address of your router. You can find it with `ip route | grep default`

9. Finally, build and run the `ravel` binary:

```
go build -o ravel -v ./cmd/
sudo ./example-bgp-command.sh
```

Which contains the following command:

```
./ravel bgp --nodename="minikube" \
	--config-key="minikube" \
	--config-namespace="platform-load-balancer" \
    --config-name="kube2ipvs" \
	--compute-iface="lo" \
	--primary-ip="lo" \
	--gateway="lo" \
	--kubeconfig="/home/andrew/.kube/config" \
	--stats-enabled="true" \
	--stats-interface="lo" \
	--stats-port=10120 \
    --auto-configure-service="kube-system/unicorns:http" \
    --auto-configure-port=70
```


Upon running, you should be able to see this output:

```
sudo ipvsadm -Ln
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.11.12.14:70 wrr
  -> 192.168.99.100:70            Tunnel  0      0          0         
TCP  10.11.12.14:8080 wrr
  -> 192.168.99.100:8080          Route   1      0          0 
```

And you should be able to ping the backend service:

```
 ~/go/src/github.com/comcast/ravel/dev-setups ⎇ feature/dev-setups: curl 10.11.12.14:8080
 You cannot teach beginners top-down programming, because they don't know which end is up. - C.A.R. Hoare 🐼
```
