# Project-5
In directory *mininet simulator*, there are the source code, two sample topologies and commands to run the simulatiom.\\
In directory *testbed*, there are the source code and commands to run the controller and exchange packets between hosts.
## MPLS route management
Starting from a multipath network with multiple disjoint paths from a source and 
a destination, a Ryu application has been implemented to set up a pair of MPLS link‐disjoint tunnels to connect the source with the destination.
One tunnel is the default path, the other is the back‐up path.
MPLS connection is based on source and destination MACs.
The application is able to re‐route traffic on the back‐up path in case of a failure 
of a link of the default path and to restore the original ruleset when the default path returns to  a working state.

### Connection set up
h1 wants to establish a TCP connection with h2.
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

### Additional checks
The code provides also some additional checks:

*  If only one path exists, the controller will install only the default one;

*  If either one or both default and back-up paths aren’t available anymore,
the relative rules on the switches are temporarily deleted until the connections return active.

The user is always notified about all issues.




## Code implementation

### IPv4 PacketIn
```python
#mpls connection setup
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
						self.send_arp(datapath, opcode, src_MAC, srcIp, dst_MAC, dst_Ip, outPort)
```
When an IPv4 packet arrives to the controller, after saving all information about source, destination and switch node, a hash function is performed with the source and destination mac addresses as inputs.
If the result is not found in in `self.mpls_conn_list`, it means that the packet belongs to a new kind of connection, therefore a new tunnel must be installed.
Before proceeding with the installation, controller checks whether the datapath id of the destination is known: in case of negative response, a broadcast ARP request is sent through the network in order to get the missing information and the hash is removed from `self.mpls_conn_list`.

``` python
#If controller has all parameters, installs MPLS connection 
if (install_flg == 1):
print("Installing %s %s mpls connection..." %(src_ip, dst_ip))

self.dpid_to_mac[dpid_src] = src
self.dpid_to_mac[dpid_dst] = dst
command = ofproto.OFPFC_ADD

#Compute all possible disjoint paths between src and dst 
G = self.net
path_list = list(nx.edge_disjoint_paths(G, dpid_src, dpid_dst))

onepath = 0
modify_dfl = 1

labeldfl = self.assign_label()
labelbu = labeldfl+1
#store paths in a list, labels are used as index
self.dfl_paths[str(labeldfl)] = path_list[0]
self.ONdfl_flg[str(new_label)] = 1
self.ONbu_flg[str(labelbu)] = 0

if (len(path_list) == 0):
self.logger.info("No paths found")

else:
if(len(path_list) == 1):
	self.logger.info("Only one path found")
	print("Label dfl: %d" %labeldfl)
	onepath = 1
	labelbu = None
else:
	self.logger.info("DFL and BU paths found")
	print("Label dfl: %d" %labeldfl)
	print("Label bu: %d" %labelbu)
	self.label_bu_list.append(labelbu)
	self.ONbu_flg[str(labelbu)] = 1
	self.bu_paths[str(labelbu)] = path_list[1]


self.add_mpls_connection(dpid_src, dpid_dst, datapath, command, labeldfl, labelbu, onepath, src_MAC, dst_MAC, modify_dfl)
self.timeStop= time.clock()
self.interval= self.timeStop- self.timeStart
self.timeStart=0

path = "ryu/ryu/app/interval_test.txt"
out_file = open(path,"a")

out_file.write('     %f		' % self.interval)
out_file.close()
self.logger.info(" interval %f " % self.interval)



#pkt forwarding
outPort = self.net[dpid_src][path_list[0][1]]['port']
actions = [parser.OFPActionPushMpls(),
	parser.OFPActionSetField(mpls_label=labeldfl),
	parser.OFPActionOutput(outPort)]
out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
datapath.send_msg(out)	
```
If `install_flg == 1`, then all of the information required to install the paths are present, and the command `nx.edge_disjoint_paths` computes all the available edge-disjoint paths in the network.
Default and back-up paths (if found) are stored and a label is assigned to each one. Stored paths are indexed with their label.
The `self.add_mpls_connection` command allow to install rules related to paths (both default and back-up at the same time) on the correspondent nodes of the network.
Finally, the packet is sent to the next node of the default path using the MPLS tunnel just installed.
In case no paths are available, an error message appears in the log.

### Label assignment
``` python
def assign_label(self):

	global new_label

	if not self.label_dfl_list:
		new_label = random.randint(1, 1000)
	else:
		new_label = random.randint(1, 1000)
		while ((new_label in self.label_dfl_list) and (new_label+1 in self.label_bu_list)):
			new_label = random.randint(1, 1000)
	self.label_dfl_list.append(new_label)
	return new_label
```
This function randomizes a label number in the range (1, 1000) and checks whetwer the label is already assigned to another tunnel.
Process is repeated until an available label is found.
`new_label+1` is the label assigned to the back-up path in order to get a correlation between the two tunnels.

### MPLS rules installation
``` python
def add_mpls_connection(self, dpid_src, dpid_dst, datapath, command, labeldfl, labelbu, onepath, src_MAC, dst_MAC, modify_dfl):
	parser = datapath.ofproto_parser
	ofp = datapath.ofproto
	#Definition of MPLS default rules for source and destination nodes. 
	#With push MPLS command, the label is attached on the packet. Label is then removed by pop MPLS command.
	if (modify_dfl == 1):
		#cycling all nodes in default path
		for i in range(0, len(self.dfl_paths[str(labeldfl)])):
			if (i == 0):
				if (self.dfl_paths[str(labeldfl)][i] == self.mac_to_dpid[src_MAC]):
					
					in_port = self.mac_to_port[dpid_src][src_MAC]
					
					#push mpls dfl src node
					outport1 = self.G[dpid_src][(self.dfl_paths[str(labeldfl)][i+1])]['port']
					match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=src_MAC, eth_dst=dst_MAC, in_port=in_port)
					actions1 = [parser.OFPActionPushMpls(),
							parser.OFPActionSetField(mpls_label=labeldfl),
							parser.OFPActionOutput(outport1)]
					self.add_flow(datapath, 2, match1, actions1, command)
					
					#print (ether_types.ETH_TYPE_IP, src_MAC, dst_MAC, in_port, labeldfl, datapath, outport1)
						
					#pop mpls dfl src node
					match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
					actions2 = [parser.OFPActionPopMpls(),
							parser.OFPActionOutput(in_port)]
					self.add_flow(datapath, 2, match2, actions2, command)
				
							
			elif (i == (len(self.dfl_paths[str(labeldfl)])-1)): 
						
				if (self.dfl_paths[str(labeldfl)][i] == dpid_dst):
						
					currentdatapath = self.datapaths[self.dfl_paths[str(labeldfl)][i]]
					outport1 = self.mac_to_port[dpid_dst][dst_MAC]
					outport2 = self.G[dpid_dst][self.dfl_paths[str(labeldfl)][i-1]]['port']
				
					#push mpls dfl dst node
					match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, eth_src=src_MAC, eth_dst=dst_MAC, in_port=outport2)
					actions1 = [parser.OFPActionPopMpls(),
							parser.OFPActionOutput(outport1)]
					self.add_flow(currentdatapath, 2, match1, actions1, command)
						
					#pop mpls dfl dst node
					match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
					actions2 = [parser.OFPActionPushMpls(),
							parser.OFPActionSetField(mpls_label=labeldfl),
							parser.OFPActionOutput(outport2)]
					self.add_flow(currentdatapath, 2, match2, actions2, command)
				
			#MPLS default rules definition for intermediate nodes: packet is forwarded according to its label.		
			else:
						
				currentdatapath = self.datapaths[self.dfl_paths[str(labeldfl)][i]]
				outport1 = self.G[self.dfl_paths[str(labeldfl)][i]][self.dfl_paths[str(labeldfl)][i+1]]['port']
				outport2 = self.G[self.dfl_paths[str(labeldfl)][i]][self.dfl_paths[str(labeldfl)][i-1]]['port']
						
				#forward mpls dfl packet intermediate node
				match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, eth_src=src_MAC, eth_dst=dst_MAC, in_port=outport2)
				actions1 = [parser.OFPActionOutput(outport1)]
				self.add_flow(currentdatapath, 2, match1, actions1, command)
					
				#backward mpls dfl packet intermediate node
				match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
				actions2 = [parser.OFPActionOutput(outport2)]
				self.add_flow(currentdatapath, 2, match2, actions2, command)
```
The function cyclically runs through all nodes of the given path (`[self.dfl_paths[str(labeldfl)][i]` variable), installing a "MPLS PUSH" command on the first and a "MPLS POP" on the last.
Intermediate nodes only have forwarding rules based on the MPLS label matching.
The `self.mac_to_port` and `self.G` variables allowes to get all the information about port numbers and MAC addresses. This kind of data are collected at the launch of the topology, by analyzing all the ARP packets that pass through the controller.
The same procedure is applied to the back-up tunnel but with a lower priority, then the function stops.

### Managing tunnels
``` python
def port_to_string(self, datapath, port):
	ofp = datapath.ofproto
	dpid = datapath.id
	out = "  Port %d (%s, hw_addr:%s)\n" % (port.port_no, port.name,
                                       		port.hw_addr)
	out += "    Configuration:"

	if port.config & ofp.OFPPC_PORT_DOWN:
		out += "      Port is administratively down (OFPPC_PORT_DOWN)\n"
		
	elif port.config & ofp.OFPPC_NO_RECV:
		out += "      Drop all packets received by port (OFPPC_NO_RECV)\n"

	elif port.config & ofp.OFPPC_NO_FWD:
		out += "      Drop packets forwarded to port (OFPPC_NO_FWD)\n"
		
	elif port.config & ofp.OFPPC_NO_PACKET_IN:
		out += "      Do not send packet-in msgs for port (OFPPC_NO_PACKET_IN)\n"

	out += "    State:"
	
	modify_flg = 0

	if port.state & ofp.OFPPS_LINK_DOWN:
		out += "      No physical link present (OFPPS_LINK_DOWN)\n"
		command = ofp.OFPFC_DELETE_STRICT
		modify_flg = 1

	elif port.state & ofp.OFPPS_BLOCKED:
		out += "      Port is blocked (OFPPS_BLOCKED)\n"
		
	elif port.state & ofp.OFPPS_LIVE:
		out += "      Live for Fast Failover Group (OFPPS_LIVE)\n"
		
	else:
		out += "      Physical link present\n"
		command = ofp.OFPFC_ADD
		modify_flg = 1
		
		
	out += "    Current Speed: %dkbps\n" % port.curr_speed
	out += "    Max Speed: %dkbps\n" % port.max_speed
	
	#when a link goes down/return active
	if (modify_flg == 1):
		
		#For each existing label, control if nodes are involved in a linkdown/linkup msg
		#If one node is detected, rules are deleted/reinstalled in all nodes of the corresponding dft path
		for label in self.label_dfl_list:
			if (dpid in self.dfl_paths[str(label)]):
				if (dpid!=self.dfl_paths[str(label)][0] and dpid!=self.dfl_paths[str(label)][len(self.dfl_paths[str(label)])-1]):
					
					dpid_src = self.dfl_paths[str(label)][0]
					dpid_dst = self.dfl_paths[str(label)][len(self.dfl_paths[str(label)])-1]
					datapath_src = self.datapaths[dpid_src]
					onepath = 1
					modify_dfl = 1
					labeldfl = label
					labelbu = None
					#print (self.dpid_to_mac)
					dst = self.dpid_to_mac[dpid_dst]
					src = self.dpid_to_mac[dpid_src]

					if(self.startmodify==0):
						self.startmodify=time.clock()
					
					if (command == ofp.OFPFC_DELETE_STRICT):
						self.ONdfl_flg[str(labeldfl)] = 0
						print("Mpls path %d (dfl) temporarily down\n" %labeldfl)
					elif (command == ofp.OFPFC_ADD):
						self.ONdfl_flg[str(labeldfl)] = 1
						print("Mpls path %d (dfl) reinstalled\n" %labeldfl)

					if (self.ONdfl_flg[str(labeldfl)]==0 and self.ONbu_flg[str(labeldfl+1)]==0):
						print("Both dfl and bu paths are not available between switch %d and %d \n" %(dpid_src, dpid_dst))
					
					self.add_mpls_connection(dpid_src, dpid_dst, datapath_src, command, labeldfl, labelbu, onepath, src, dst, modify_dfl)

		#Same as before for the bu path		
		for label in self.label_bu_list:
			if (dpid in self.bu_paths[str(label)]):
				if (dpid!=self.bu_paths[str(label)][0] and dpid!=self.bu_paths[str(label)][len(self.bu_paths[str(label)])-1]):
			
					dpid_src = self.bu_paths[str(label)][0]
					dpid_dst = self.bu_paths[str(label)][len(self.bu_paths[str(label)])-1]
					datapath_src = self.datapaths[dpid_src]
					onepath = 0
					modify_dfl = 0
					labeldfl = None
					labelbu = label
					#print (self.dpid_to_mac)
					dst = self.dpid_to_mac[dpid_dst]
					src = self.dpid_to_mac[dpid_src]

					if(self.startmodify==0):
						self.startmodify=time.clock()
					
					if (command == ofp.OFPFC_DELETE_STRICT):
						self.ONbu_flg[str(labelbu)] = 0
						print("Mpls path %d (bu) temporarily down\n" %labelbu )
					elif (command == ofp.OFPFC_ADD):
						self.ONbu_flg[str(labelbu)] = 1
						print("Mpls path %d (bu) reinstalled\n" %labelbu)

					if (self.ONdfl_flg[str(labelbu-1)]==0 and self.ONbu_flg[str(labelbu)]==0):
						print("Both dfl and bu paths are not available between switch %d and %d " %(dpid_src, dpid_dst))
						
					self.add_mpls_connection(dpid_src, dpid_dst, datapath_src, command, labeldfl, labelbu, onepath, src, dst, modify_dfl)


	return out 
```
The `port_to_string` funcion is a Ryu function that sends a status packet to the controller whenever a port update is detected.
Port update includes: Port Down event, Port Alive event, Port Modify event. This kind of events also involve the link status, since when a link breaks, the ports go down and viceversa.
When the function reveals that a port update message includes an added or a dying link, `modify_flg` is set to 1.
Then the algorithm checks if the datapath from where the message was originated is included in an active path.
Different scenarios can occur:

* PortDown and Datapath belong to a default path: default path is marked as "not active" (`self.ONdfl_flg[str(labeldfl)] = 0`) and rules are deleted from all nodes. Packets will follow the back-up path (if available).
* PortDown and Datapath belong to a back-up path: back-up path is marked as "not active" (`self.ONbu_flg[str(labelbu)] = 0`) and rules are deleted from all nodes.
* PortAlive and Datapath belong to a default path: default path is marked as "active" (`self.ONdfl_flg[str(labeldfl)] = 1`) and rules are installed in all nodes. Packets will stop follow the back-up path (if available).
* PortAlive and Datapath belong to a back-up path: default path is marked as "active" (`self.ONbu_flg[str(labeldfl)] = 1`) and rules are installed in all nodes.

If no path remains available, an error message is reported in the log.

