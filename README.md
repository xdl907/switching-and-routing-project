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

