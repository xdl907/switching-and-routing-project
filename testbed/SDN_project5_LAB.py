# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
import random
import ipaddr
import time
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp, mpls
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath

NUMBER_OF_SWITCH_PORTS = 3
IP_ADDRESS_CONTROLLER = '10.10.5.24'
NETMASK_SDN_NETWORK = 24


def ip2bin(ip_addr, net_mask):
	ip_bin_1 = bin(int(ipaddr.IPv4Address(ip_addr)))
	ip_bin = ip_bin_1[2:net_mask-1]
	return ip_bin

NET_SDN = ip2bin(IP_ADDRESS_CONTROLLER, NETMASK_SDN_NETWORK)


class ZodiacSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}

	def __init__(self, *args, **kwargs):
		super(ZodiacSwitch, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.mac_to_port = {}
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links1 = []
		self.links2 = []
		self.no_of_nodes = 0
		self.no_of_links = 0		
		self.datapaths = {}
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.host_list = []
		self.ip_to_mac = {}
		self.ip_to_mac[IP_ADDRESS_CONTROLLER] = '18:03:73:db:86:82'
		self.port_occupied = {}
		self.GLOBAL_VARIABLE = 0
		self.label_dfl_list = []
		self.label_bu_list = []
		self.mpls_conn_list = []
		self.ONdfl_flg = {}
		self.ONbu_flg = {}
		self.dfl_paths = {}
		self.bu_paths = {}
		self.dpid_to_mac = {}
		self.switches = []
		self.G = nx.DiGraph()
		self.timestart = 0
		self.timestop = 0
		self.startmodify = 0
		self.stopmodify = 0
		
	#Default rule definition for all switches of the network. No buffering, the whole packet is forwarded to the controller
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# port request
		req = parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)

		
		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
		command = ofproto.OFPFC_ADD
		
		self.add_flow(datapath, 0, match, actions, command)

	#Triggered every time network pattern changes 
	def get_topology_data(self):

		switch_list = get_switch(self.topology_api_app, None)   
		self.switches=[switch.dp.id for switch in switch_list]
		#print(switches)
		if self.GLOBAL_VARIABLE == 0:
			for s in self.switches:
				for switch_port in range(1, NUMBER_OF_SWITCH_PORTS+1):
					self.port_occupied.setdefault(s, {})
					# we suppose every port occupied (= 0)
					self.port_occupied[s][switch_port] = 0		
			#self.GLOBAL_VARIABLE = 1
		#print(self.port_occupied)
		self.net.add_nodes_from(self.switches)
		self.G.add_nodes_from(self.switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		self.G.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		self.G.add_edges_from(links)
		links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
		# If there is a link attached to the port, then it is occupied (=1)
		for l in links_:
			self.port_occupied[l[0]][l[2]] = 1

	#Rule installation function
	def add_flow(self, datapath, priority, match, actions, command, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
												actions)]

		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, command=command,
									 out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match, instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=command,
									match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, instructions=inst)
		datapath.send_msg(mod)
		
	#installation and removal of MPLS rules
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
						match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
						actions2 = [parser.OFPActionPopMpls(),
								parser.OFPActionOutput(in_port)]
						self.add_flow(datapath, 2, match2, actions2, command)
					
								
				elif (i == (len(self.dfl_paths[str(labeldfl)])-1)): 
							
					if (self.dfl_paths[str(labeldfl)][i] == dpid_dst):
							
						currentdatapath = self.datapaths[self.dfl_paths[str(labeldfl)][i]]
						outport1 = self.mac_to_port[dpid_dst][dst_MAC]
						outport2 = self.G[dpid_dst][self.dfl_paths[str(labeldfl)][i-1]]['port']
					
						#pop mpls dfl dst node
						match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=src_MAC, eth_dst=dst_MAC, in_port=outport2)
						actions1 = [parser.OFPActionPopMpls(),
								parser.OFPActionOutput(outport1)]
						self.add_flow(currentdatapath, 2, match1, actions1, command)
							
						#push mpls dfl dst node
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
					match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=src_MAC, eth_dst=dst_MAC, in_port=outport2)
					actions1 = [parser.OFPActionOutput(outport1)]
					self.add_flow(currentdatapath, 2, match1, actions1, command)
						
					#backward mpls dfl packet intermediate node
					match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
					actions2 = [parser.OFPActionOutput(outport2)]
					self.add_flow(currentdatapath, 2, match2, actions2, command)
			
		#Definition of MPLS backup rules for source and destination nodes. 
		#With push MPLS command, the label is attached on the packet. Label is then removed by pop MPLS command.	
		if (onepath == 0):
			for i in range(0, len(self.bu_paths[str(labelbu)])):
				if (i == 0):
					if (self.bu_paths[str(labelbu)][i] == self.mac_to_dpid[src_MAC]):
					
						#push mpls bu scr node
						in_port = self.mac_to_port[dpid_src][src_MAC]
						outport1 = self.G[dpid_src][self.bu_paths[str(labelbu)][i+1]]['port']
						match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=src_MAC, eth_dst=dst_MAC)
						actions1 = [parser.OFPActionPushMpls(),
							parser.OFPActionSetField(mpls_label=labelbu),
							parser.OFPActionOutput(outport1)]
						self.add_flow(datapath, 1, match1, actions1, command)
						
						#pop mpls bu scr node
						match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
						actions2 = [parser.OFPActionPopMpls(),
							parser.OFPActionOutput(in_port)]
						self.add_flow(datapath, 1, match2, actions2, command)
					
				elif (i == (len(self.bu_paths[str(labelbu)])-1)): 
		
					if (self.bu_paths[str(labelbu)][i] == dpid_dst):
						
						currentdatapath = self.datapaths[self.bu_paths[str(labelbu)][i]]
						outport1 = self.mac_to_port[dpid_dst][dst_MAC]
						outport2 = self.G[dpid_dst][self.bu_paths[str(labelbu)][i-1]]['port']
				
						#pop mpls bu dst node
						match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=src_MAC, eth_dst=dst_MAC, in_port=outport2)
						actions1 = [parser.OFPActionPopMpls(),
							parser.OFPActionOutput(outport1)]
						self.add_flow(currentdatapath, 1, match1, actions1, command)
				
						#push mpls bu dst node
						match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=dst_MAC, eth_dst=src_MAC)
						actions2 = [parser.OFPActionPushMpls(),
							parser.OFPActionSetField(mpls_label=labelbu),
							parser.OFPActionOutput(outport2)]
						self.add_flow(currentdatapath, 1, match2, actions2, command)
						
				else:
						
					currentdatapath = self.datapaths[self.bu_paths[str(labelbu)][i]]
					outport1 = self.G[self.bu_paths[str(labelbu)][i]][self.bu_paths[str(labelbu)][i+1]]['port']
					outport2 = self.G[self.bu_paths[str(labelbu)][i]][self.bu_paths[str(labelbu)][i-1]]['port']
						
					#forward mpls bu packet intermediate node
					match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=src_MAC, eth_dst=dst_MAC, in_port=outport2)
					actions1 = [parser.OFPActionOutput(outport1)]
					self.add_flow(currentdatapath, 1, match1, actions1, command)
						
					#backward mpls bu packet intermediate node
					match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, eth_src=dst_MAC, eth_dst=src_MAC, in_port=outport1)
					actions2 = [parser.OFPActionOutput(outport2)]
					self.add_flow(currentdatapath, 1, match2, actions2, command)

		if (command == ofp.OFPFC_ADD):
			self.logger.info("MPLS connection installed")
		
	#ARP delivery function
	def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
		if opcode == 1:
			targetMac = "00:00:00:00:00:00"
			targetIp = dstIp
		elif opcode == 2:
			targetMac = dstMac
			targetIp = dstIp

		e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
	
		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
				datapath=datapath,
				buffer_id=0xffffffff,
				in_port=datapath.ofproto.OFPP_CONTROLLER,
				actions=actions,
				data=p.data)
		datapath.send_msg(out)


	#Packet in handler: controller extracts packet fields
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
						ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		dst = eth.dst
		src = eth.src
		dpid_src = datapath.id
		
		# TOPOLOGY DISCOVERY------------------------------------------
		
		self.get_topology_data()

		# MAC LEARNING-------------------------------------------------
		
		if src not in self.host_list:
			self.host_list.append(src)
			self.mac_to_port.setdefault(dpid_src, {})
			self.port_to_mac.setdefault(dpid_src, {})
			self.mac_to_port[dpid_src][src] = in_port
			self.mac_to_dpid[src] = dpid_src
			self.port_to_mac[dpid_src][in_port] = src


		# HANDLE ARP PACKETS--------------------------------------------
		   
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_packet = pkt.get_protocol(arp.arp)
			arp_dst_ip = arp_packet.dst_ip
			arp_src_ip = arp_packet.src_ip
			#self.logger.info("It is an ARP packet")	
			#self.logger.info("Packet in: Source MAC %s Source ARP IP %s Dest MAC %s Dest ARP IP %s", src, arp_src_ip, dst, arp_dst_ip)
			#self.logger.info("Packet in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src, dst, in_port)
			# If it is an ARP request
			if arp_packet.opcode == 1:
				#self.logger.info("It is an ARP request")	
				if arp_dst_ip in self.ip_to_mac:
					#self.logger.info("The address is inside the IP TO MAC table")
					srcIp = arp_dst_ip
					dstIp = arp_src_ip
					srcMac = self.ip_to_mac[arp_dst_ip]
					dstMac = src
					outPort = in_port
					opcode = 2
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
					#self.logger.info("packet in %s %s %s %s", srcMac, srcIp, dstMac, dstIp)
				else:
					#self.logger.info("The address is NOT inside the IP TO MAC table")
					self.logger.info("arpPacket in: Source MAC %s Source ARP IP %s Dest MAC %s Dest ARP IP %s", src, arp_src_ip, dst, arp_dst_ip)
					srcIp = arp_src_ip
					dstIp = arp_dst_ip
					srcMac = src
					dstMac = dst
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac 
					# Send and ARP request to all the switches
					opcode = 1
					for id_switch in self.switches:
						datapath_dst = get_datapath(self, id_switch)
						for po in range(1,len(self.port_occupied[id_switch])+1):
							if self.port_occupied[id_switch][po] == 0:
							# If the port is occupied
								outPort = po
								if id_switch == dpid_src:
									if outPort != in_port:
										self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
								else:
									self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
	
			else:
				#self.logger.info("It is an ARP reply")
				srcIp = arp_src_ip
				dstIp = arp_dst_ip
				srcMac = src
				dstMac = dst
				if arp_dst_ip in self.ip_to_mac:
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac
							# Send and ARP reply to the switch
				opcode = 2
				outPort = self.mac_to_port[self.mac_to_dpid[dstMac]][dstMac]
				datapath_dst = get_datapath(self, self.mac_to_dpid[dstMac])
				self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

				   
		# HANDLE IP PACKETS-----------------------------------------------
			
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:
			
			if (self.timestart == 0):
				self.timestart = time.clock()
			
			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			src_MAC = src
			dst_MAC = dst
			
			self.logger.info("ipPacket in: Source MAC %s Source IP %s Dest MAC %s Dest IP %s", src, src_ip, dst, dst_ip)

			if (dst_MAC == "ff:ff:ff:ff:ff:ff"):
				self.logger.info("It is BROADCAST MAC")
				return
			
			NET_PACKET = ip2bin(dst_ip, NETMASK_SDN_NETWORK)
			if NET_SDN == NET_PACKET:
			#If dst_ip!='10.79.1.24' and dst_ip!='255.255.255.255' and dst_ip!='224.0.0.251' and dst_ip!='169.254.41.206':
				proto  = str(ip4_pkt.proto)
				sport = "0"
				dport = "0" 
				if proto == "6":
					tcp_pkt = pkt.get_protocol(tcp.tcp)
					sport = str(tcp_pkt.src_port)
					dport = str(tcp_pkt.dst_port)
					   
				if proto == "17":
					udp_pkt = pkt.get_protocol(udp.udp)
					sport = str(udp_pkt.src_port)
					dport = str(udp_pkt.dst_port)

			#Mpls connection setup
			scrDst_list = [src, dst] 
			scrDst_list.sort()

			#Verify if connection between the two host is already installed
			if (hash((scrDst_list[0], scrDst_list[1])) not in self.mpls_conn_list): 
				self.mpls_conn_list.append(hash((scrDst_list[0], scrDst_list[1])))
				#self.logger.info(self.mpls_conn_list)		
				
				#Verify if controller knows the pair dstMAC/dpid
				#If not send a BROADCAST ARP REQUEST
				install_flg = 1
				try:
					dpid_dst = self.mac_to_dpid[dst_MAC] 
				except:
					self.logger.info("Destination MAC unknown, sending ARP request...")
					self.logger.info (dst_MAC)
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
			
				#If controller has all parameters, installs MPLS connection 
				if (install_flg == 1):
					self.logger.info("Installing %s %s mpls connection..." %(src_ip, dst_ip))

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
					#Store paths in a list, labels are used as index
					self.dfl_paths[str(labeldfl)] = path_list[0]
					self.ONdfl_flg[str(new_label)] = 1
					self.ONbu_flg[str(labelbu)] = 0

					if (len(path_list) == 0):
						self.logger.info("No paths found")
						
					else:
						if(len(path_list) == 1):
							self.logger.info("Only one path found")
							self.logger.info("Label dfl: %d" %labeldfl)
							onepath = 1
							labelbu = None
						else:
							self.logger.info("DFL and BU paths found")
							self.logger.info("Label dfl: %d" %labeldfl)
							self.logger.info("Label bu: %d" %labelbu)
							self.label_bu_list.append(labelbu)
							self.ONbu_flg[str(labelbu)] = 1
							self.bu_paths[str(labelbu)] = path_list[1]

		
						self.add_mpls_connection(dpid_src, dpid_dst, datapath, command, labeldfl, labelbu, onepath, src_MAC, dst_MAC, modify_dfl)
				        
				        #Statistics
						self.timestop = time.clock()
						interval = self.timestop - self.timestart
						out_file = open("/home/bonsai/ryu/ryu/app/Project5_time_stats.txt","a")
						out_file.write('%f\n' %interval)
						out_file.close()
						self.timestart = 0
						self.logger.info("Time for installation: %f" %interval)

						#Pkt forwarding
						outPort = self.net[dpid_src][path_list[0][1]]['port']
						actions = [parser.OFPActionPushMpls(),
							parser.OFPActionSetField(mpls_label=labeldfl),
							parser.OFPActionOutput(outPort)]
						out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
						datapath.send_msg(out)	
			
	#Generate randomly labels		
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

	#Update topology when a new switch joins
	@set_ev_cls(event.EventSwitchEnter)
	def switchEnter(self, ev):
		self.get_topology_data()
	
	#Triggered every time a new port is detected
	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		"""Handles response to the Port Desc Stats request"""
		datapath = ev.msg.datapath
		ofp = datapath.ofproto
		parser = datapath.ofproto_parser

		self.datapaths[datapath.id] = datapath
		#print(self.datapaths)

		self.logger.info("Received port list:")
		for port in ev.msg.body:
				print(self.port_to_string(datapath, port))

	#Triggered every time an existing port changes its status
	@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
	def port_status_handler(self, ev):
		"""Handles async Port Status messages"""
		msg = ev.msg
		ofp = msg.datapath.ofproto
		datapath = msg.datapath
		self.datapaths[datapath.id] = datapath

		reason = {
			ofp.OFPPR_ADD: "Port was added",
			ofp.OFPPR_DELETE: "Port was deleted",
			ofp.OFPPR_MODIFY: "Port was modified"
		}.get(msg.reason, "Unknown reason (%d)" % msg.reason)

		self.logger.info("\n\nReceived port status update: %s" % reason)
		self.logger.info(self.port_to_string(msg.datapath, msg.desc))

		#clear and reload topology when a port is modified
		self.net.clear()
		self.port_occupied.clear()
		self.get_topology_data()


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
			command = ofp.OFPFC_ADD
			modify_flg = 1
		else:
			out += "      Physical link present\n"
			command = ofp.OFPFC_ADD
			modify_flg = 1
			
			
		out += "    Current Speed: %dkbps\n" % port.curr_speed
		out += "    Max Speed: %dkbps\n" % port.max_speed
		
		#when a link goes down/return active
		if (modify_flg == 1):
			
			#For each existing label, control if nodes are involved in a linkdown/linkup msg
			#If one node is detected, rules are deleted/reinstalled in all nodes of the corresponding dfl path
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
                        
                        #Statistics
						if (self.startmodify == 0):
							self.startmodify = time.clock()
						
						if (command == ofp.OFPFC_DELETE_STRICT):
							self.ONdfl_flg[str(labeldfl)] = 0
							self.logger.info("Mpls path %d (dfl) temporarily down\n" %labeldfl)
						elif (command == ofp.OFPFC_ADD):
							self.ONdfl_flg[str(labeldfl)] = 1
							self.logger.info("Mpls path %d (dfl) reinstalled\n" %labeldfl)

						if (self.ONdfl_flg[str(labeldfl)]==0 and self.ONbu_flg[str(labeldfl+1)]==0):
							self.logger.info("Both dfl and bu paths are not available between switch %d and %d \n" %(dpid_src, dpid_dst))
						
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

						if (self.startmodify == 0):
							self.startmodify = time.clock()
						
						if (command == ofp.OFPFC_DELETE_STRICT):
							self.ONbu_flg[str(labelbu)] = 0
							self.logger.info("Mpls path %d (bu) temporarily down\n" %labelbu )
						elif (command == ofp.OFPFC_ADD):
							self.ONbu_flg[str(labelbu)] = 1
							self.logger.info("Mpls path %d (bu) reinstalled\n" %labelbu)

						if (self.ONdfl_flg[str(labelbu-1)]==0 and self.ONbu_flg[str(labelbu)]==0):
							self.logger.info("Both dfl and bu paths are not available between switch %d and %d " %(dpid_src, dpid_dst))
							
						self.add_mpls_connection(dpid_src, dpid_dst, datapath_src, command, labeldfl, labelbu, onepath, src, dst, modify_dfl)
            #Statistics
			if (self.startmodify != 0):
				self.stopmodify = time.clock()
				interval = self.stopmodify - self.startmodify
				out_file = open("/home/bonsai/ryu/ryu/app/Project5_timemodify_stats.txt","a")
				out_file.write('%f\n' %interval)
				out_file.close()
				self.startmodify = 0
				self.logger.info("Time for modifying: %f" %interval)

		return out


app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')	
