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

