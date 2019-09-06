# Project-5
## MPLS route management
Starting from a multipath network with multiple disjoint paths from a source and 
a destination, a Ryu application has been implemented to set up a pair of MPLS link‐disjoint tunnels to connect the source with the destination.
One tunnel is the default path, the other is the back‐up path.
MPLS connection is based on source and destination MACs.
The application is able to re‐route traffic on the back‐up path in case of a failure 
of a link of the default path and to restore the original ruleset when the default path returns to  a working state.

### MPLS connection set up
h1 wants to establish an IP connection with h2.
All the flow tables of the switches inside the network are empty (only the default rule is installed).
When the first IP packet comes to the switch connected to h1, the controller installs the MPLS flows in the switches of the default and backup paths.

### Packet in handler
Once the topology and border switches are known, the controller computes a list of link-disjoint path, which is sorted by increasing number of edges.
The first entry in the list is selected as the default path, assigning a label value chosen randomly.
The second entry is the backup path and its label is the default one incremented by 1.
If the list contains just one element, only the default path will be available.

### Rule installation
The controller installs a MPLS PUSH rule in order to add labels on packets passing through the node directly connected to the host.
Intermediate nodes contain only forwarding rules based on label matching.
In the last node a POP MPLS rule is installed in order to remove the label from the packet and deliver it to the host.
At the same time symmetrical rules are placed to allow packets to come back on the same path.
Intermediate switches are able to recognize the direction of the packets by checking the input port.
The same procedure is applied to the backup path, but its rules have a lower priority than the default ones.

### Port detection
The user is warned about the link status through a set of messages that come up every time the topology is modified.
When a link goes up/down, the port status of the switches involved in the connection will change consequently.
The switches notify the event to the controller with port status messages.

### Addictional checks
The code provides also some additional checks:

*  If only one path exists, the controller will install only the default one;

*  If either one or both default and back-up paths aren’t available anymore,
the relative rules on the switches are temporarily deleted until the connections return active.

The user is always notified about all issues.



## Code implementation

### IPv4 PacketIn
*#mpls connection setup
			scrDst_list = [src, dst] 
			scrDst_list.sort()

			#verify if connection between the two host is already installed
			if (hash((scrDst_list[0], scrDst_list[1])) not in self.mpls_conn_list): 
				self.mpls_conn_list.append(hash((scrDst_list[0], scrDst_list[1])))
				#self.logger.info(self.mpls_conn_list)		
				
				#Verify if controller knows the pair dstMAC/dpid
				#If not send a BROADCAST ARP REQUEST
				install_flg = 1
				try:
					dpid_dst = self.mac_to_dpid[dst_MAC] 
				except:
					print("Destination MAC unknown, sending ARP request...")
					self.mpls_conn_list.remove(hash((scrDst_list[0], scrDst_list[1])))
					install_flg = 0 
					opcode = 1
					dst_MAC = "ff:ff:ff:ff:ff:ff"
					for po in range(1,len(self.port_occupied[dpid_src])+1):
							if self.port_occupied[dpid_src][po] == 0:
							# If the port is occupied
								outPort = po
								if outPort != in_port:
									self.send_arp(datapath, opcode, src_MAC, srcIp, dst_MAC, dst_Ip, outPort)*
















