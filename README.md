# project-5
## MPLS route management

Starting from a multipath network with multiple disjoint paths from a source and 
a destination, a Ryu application has been implemented to set up a pair of MPLS link‐disjoint tunnels to connect the source with the destination.
One tunnel is the default path, the other is the back‐up path.
MPLS connection is based on source and destination MACs.
The application is able to re‐route traffic on the back‐up path in case of a failure 
of a link of the default path and to restore the original ruleset when the default path returns to  a working state.




### Template: sar_application_SDN.py

### Source: http://ryu.readthedocs.io/en/latest/getting_started.html

# Commands for mininet simulation

Boot the controller
>   PYTHONPATH=. ./ryu/bin/ryu-manager --observe-links ryu/ryu/app/Project_Total_testbed.py

Load the topology
>  sudo mn --custom mininet/custom/topology.py --mac --topo mpls --link tc,bw=1 --controller=remote,ip=10.0.2.15,port=6633 --switch ovs,protocols=OpenFlow13

Open tshark on both hosts to show packets exchanged
>  mininet/util/m h1 tshark -f "tcp"


>  mininet/util/m h2 tshark -f "tcp"

Open host 2 in server mode
>  mininet/util/m h2 iperf -s

Open host 1 in client mode setting max length of messages (MTU) to 500 bytes
>  mininet/util/m h1 iperf -c 10.0.0.2 -M 500

Open the browser and check rule installation on *http://localhost:8282*

Simulate a link failure in the default MPLS path with
>  link s1 s3 down

Restore the previous link with 
>  link s1 s3 up

Simulate a link failure in the default and backup MPLS path with
>  link s1 s3 down

>  link s1 s4 down

Restore the previous link with 
>  link s1 s3 up













