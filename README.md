# project-5
## MPLS route management

Design a multipath network where there are multiple disjoint paths
from a source and a destination. Implement a Ryu application to set
up a pair of MPLS link‐disjoint tunnels to connect the source with
the destination. One tunnel is the working path, the other is the
back‐up path. The application must be able to re‐route traffic on
the back‐up path in case of a failure of a link of the working path.
Measure the effectiveness of the protection mechanism by
emulating link failures.

### Template: sar_application_SDN.py

### Source: http://ryu.readthedocs.io/en/latest/getting_started.html

# Commands for mininet simulation

Boot the controller
>   PYTHONPATH=. ./ryu/bin/ryu-manager --observe-links ryu/ryu/app/Project_Total_testbed.py

Load the topology
>  sudo mn --custom mininet/custom/topology.py --mac --topo mpls --link tc,bw=1 --controller=remote,ip=10.0.2.15,port=6633 --switch ovs,protocols=OpenFlow13

Open tshark on both hosts to show packets exchanged
>  mininet/util/m h1 tshark -f "tcp"
mininet/util/m h2 tshark -f "tcp"

aaaa



