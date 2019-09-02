## Commands for mininet simulation

Boot the controller

```bash
$ PYTHONPATH=. ./ryu/bin/ryu-manager --observe-links ryu/ryu/app/Project_Total_testbed.py
```

Load the topology
```bash
$ sudo mn --custom mininet/custom/topology.py --mac --topo mpls --link tc,bw=1 --controller=remote,ip=10.0.2.15,port=6633 --switch ovs,protocols=OpenFlow13
```

Open tshark on both hosts to show packets exchanged
```bash
$ mininet/util/m h1 tshark -f "tcp"

$ mininet/util/m h2 tshark -f "tcp"
```
Open host 2 in server mode
```bash
$  mininet/util/m h2 iperf -s
```
Open host 1 in client mode setting max length of messages (MTU) to 500 bytes
```bash
$  mininet/util/m h1 iperf -c 10.0.0.2 -M 500
```
Open the browser and check rule installation on *http://localhost:8282*

Simulate a link failure in the default MPLS path with
```bash
>  link s1 s3 down
```
Restore the previous link with
```bash
>  link s1 s3 up
```
Simulate a link failure in the default and backup MPLS path with
```bash
>  link s1 s3 down

>  link s1 s4 down
```
Restore the previous link with 
```bash
>  link s1 s3 up
```