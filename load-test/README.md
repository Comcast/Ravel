- `ab.yaml` is an apachebench pinned to one node against the lbtestandrew-121 service.
- to get a list of nodes, run:
```
kubectx anvil2-net-test
kubectl get nodes
- use the namespace `lb-test-andrew`
```
- to ssh to a node, use the `core` user and pass `***REMOVED***`
```
ssh core@10.131.153.77
```
- get logs for ipvs-backend:
```
journalctl -u ipvs-backend
```
- check status of ipvs-backend
```
systemctl status ipvs-backend
```
- to build the code, run `make build push` at the root of the `Ravel` code tree in the `slow-ipvs-updates` branch
- to push the new version into the cluster:
```
cd eg
cat anvil2-network-test.txt > server-list.txt
vim update-ipvs-backend.sh and set the right image tag and user at the top
./update-ipvs-backend.sh
```
