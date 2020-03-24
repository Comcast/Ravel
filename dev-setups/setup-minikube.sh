# setup mini. This takes a while
echo "#####\n# starting minikube.....\n#####"
minikube start --kubernetes-version=v1.12.7 --vm-driver=virtualbox
echo "done.\n\n"

echo "#####\n# copying kube config into cluster.....\n#####"
cp ~/.kube/config .
sed -i "s/$USER/docker/g" config
scp -r $(minikube ssh-key) config docker@$(minikube ip):/home/docker/
ssh docker@$(minikube ip) 'sudo mv /home/docker/config /etc/kubernetes/kubeconfig'
echo "done.\n"

echo "#####\n# copying certs into cluster....\n#####"
ssh docker@$(minikube ip) 'mkdir ~/.minikube'
scp -r $(minikube ssh-key) ~/.minikube/*.pem docker@$(minikube ip):.minikube/
scp -r $(minikube ssh-key) ~/.minikube/*.crt docker@$(minikube ip):.minikube/
scp -r $(minikube ssh-key) ~/.minikube/*.key docker@$(minikube ip):.minikube/
echo "done.\n"

echo "#####\n# adding netconf dir into cluster....\n#####"
scp -r $(minikube ssh-key) netconf docker@$(minikube ip):/home/docker/
ssh docker@$(minikube ip) 'sudo mv /home/docker/netconf/ /'
echo "done.\n"

echo "#####\n# creating configmap namespace....\n#####"
kubectl create ns platform-load-balancer
kubectl create -f minikube-configmap.yml

echo "#####\n# creating realserver deployment....\n#####"
kubectl create -f ./deployments/realserver/realserver.yaml

echo "#####\n# creating TCP test server to direct traffic to....\n#####"
kubectl create ns lb-test
kubectl create -f ./deployments/quote-server/quote-server.yaml
kubectl create -f ./deployments/quote-server/quote-server-service.yaml
echo "done.\n"

echo "#####\n# creating UDP test server to direct traffic to....\n#####"
kubectl create ns udp-test
kubectl create -f ./deployments/udp-server/udp-test.yaml
kubectl create -f ./deployments/udp-server/udp-test-service.yaml
echo "done.\n"


echo "#####\n# building ravel...\n#####"
go build -o ravel -v ../cmd/
echo "done.\n"

echo "run the following commands in separate terminals to run ravel:"
echo "sudo gobgpd -f bgp-configuration/gobgp.conf"
echo "sudo ./example-bgp-command.sh"
