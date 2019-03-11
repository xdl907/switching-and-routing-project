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
		self.links = {}
		self.no_of_nodes = 0
		self.no_of_links = 0		
		self.datapaths = {}
		self.switch_id = []
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.host_list = []
		self.ip_to_mac = {}
		self.ip_to_mac[IP_ADDRESS_CONTROLLER] = '18:03:73:db:86:82'
		self.port_occupied = {}
		self.lookup = {}
		self.GLOBAL_VARIABLE = 0
		self.label_list = []
		self.scrDst_list = []
		self.mpls_conn_list = []


	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
											
		self.add_flow(datapath, 0, match, actions)


	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
												actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

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
		self.datapaths[dpid_src] = datapath
		
		
		# TOPOLOGY DISCOVERY------------------------------------------
		
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]
		#print(switches)
		#print(self.GLOBAL_VARIABLE)
		if self.GLOBAL_VARIABLE == 0:
			#self.logger.info('HERE!!!!!!!!')
			for s in switches:
				for switch_port in range(1, NUMBER_OF_SWITCH_PORTS+1):
					self.port_occupied.setdefault(s, {})
					# we suppose every port occupied (= 0)
					self.port_occupied[s][switch_port] = 0		
			#self.GLOBAL_VARIABLE = 1
		#print(self.port_occupied)
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
		# If there is a link attached to the port, then it is occupied (=1)
		# print(self.port_occupied)
		for l in links_:
			self.port_occupied[l[0]][l[2]] = 1
			
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
					#self.logger.info("Packet in: Source MAC %s Source ARP IP %s Dest MAC %s Dest ARP IP %s", src, arp_src_ip, dst, arp_dst_ip)
					srcIp = arp_src_ip
					dstIp = arp_dst_ip
					srcMac = src
					dstMac = dst
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac 
					# Send and ARP request to all the switches
					opcode = 1
					for id_switch in switches:
						#if id_switch != dpid_src:
						datapath_dst = get_datapath(self, id_switch)
						# print(dpid_src)
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
			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			src_MAC = src
			dst_MAC = dst
			NET_PACKET = ip2bin(dst_ip, NETMASK_SDN_NETWORK)
			if NET_SDN == NET_PACKET:
			#if dst_ip!='10.79.1.24' and dst_ip!='255.255.255.255' and dst_ip!='224.0.0.251' and dst_ip!='169.254.41.206':
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

			#mpls connection setup
			scrDst_list = [src, dst] 
			#print scrDst_list
			scrDst_list.sort()

			#verify if connection between the two host is already installed
			if (hash((scrDst_list[0], scrDst_list[1])) not in self.mpls_conn_list): 
				self.mpls_conn_list.append(hash((scrDst_list[0], scrDst_list[1])))
				#self.logger.info(self.mpls_conn_list)

				labeldfl = self.assign_label()
				labelbu = self.assign_label()
				G = self.net
				dpid_dst = self.mac_to_dpid[dst_MAC]
				
		
				path_list = list(nx.edge_disjoint_paths(G, dpid_src, dpid_dst))
			
				if (len(path_list) == 1):
					self.logger.info("Only default path installed")
					onepath = 1
				print("questa è una prova %s"%(path_list)) 
			
				lenpath = len(path_list[0])
				for i in range(0, lenpath):
					if (i == 0):
						if (path_list[0][i] == self.mac_to_dpid[src_MAC]):
					
							print (self.mac_to_dpid[src_MAC])
							print ("Questa è la in_port di h1:%s" %(in_port))
					
							#andata mpls dfl
							outport1 = self.net[dpid_src][path_list[0][i+1]]['port']
							match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=src_MAC, eth_dst=dst_MAC)
							actions1 = [parser.OFPActionPushMpls(),
									parser.OFPActionSetField(mpls_label=labeldfl),
									parser.OFPActionOutput(outport1)]
							self.add_flow(datapath, 2, match1, actions1)
						
							#andata mpls bu
							outport2 = self.net[dpid_src][path_list[1][i+1]]['port']
							match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=src_MAC, eth_dst=dst_MAC)
							actions2 = [parser.OFPActionPushMpls(),
									parser.OFPActionSetField(mpls_label=labelbu),
									parser.OFPActionOutput(outport2)]
							self.add_flow(datapath, 1, match2, actions2)
						
							#ritorno mpls dfl
							match3 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, in_port=outport1)
							actions3 = [parser.OFPActionPopMpls(),
									parser.OFPActionOutput(in_port)]
							self.add_flow(datapath, 2, match3, actions3)
						
							#ritorno mpls bu
							match4 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labelbu, in_port=outport2)
							self.add_flow(datapath, 1, match4, actions3)
				
							current_op = outport1
							
							#pkt forwarding
							actions = [parser.OFPActionPushMpls(),
									parser.OFPActionSetField(mpls_label=labeldfl),
									parser.OFPActionOutput(current_op)]
							out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
							datapath.send_msg(out)
				
					elif (i == (lenpath-1)): 
						#print ("Questo è i:%s" %(i))
						#print ("Questo è dpid_dst:%s" %(dpid_dst))
						#print ("Questo è nodopath:%s" %(path_list[0][i]))
						#print (self.datapaths)
						
						if (path_list[0][i] == dpid_dst):
						
							print (self.datapaths)
							currentdatapath = self.datapaths[path_list[0][i]]
						
							#andata mpls dfl
							outport1 = self.mac_to_port[dpid_dst][dst]
							print ("Questa è la porta di h2: %s" %(outport1))
							match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl)
							actions1 = [parser.OFPActionPopMpls(),
									parser.OFPActionOutput(outport1)]
							self.add_flow(currentdatapath, 2, match1, actions1)
						
							#andata mpls bu
							match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labelbu)
							self.add_flow(currentdatapath, 1, match2, actions1)
						
							#ritorno mpls dfl
							outport2 = self.net[dpid_dst][path_list[0][i-1]]['port']
							print ("Questa è la porta di ritorno dfl: %s" %(outport2))
							match3 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=dst_MAC, eth_dst=src_MAC)
							actions3 = [parser.OFPActionPushMpls(),
									parser.OFPActionSetField(mpls_label=labeldfl),
									parser.OFPActionOutput(outport2)]
							self.add_flow(currentdatapath, 2, match3, actions3)
						
							#ritorno mpls bu
							outport3 = self.net[dpid_dst][path_list[1][i-1]]['port']
							print ("Questa è la porta di ritorno bu: %s" %(outport3))
							match4 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=dst_MAC, eth_dst=src_MAC)
							actions4 = [parser.OFPActionPushMpls(),
									parser.OFPActionSetField(mpls_label=labelbu),
									parser.OFPActionOutput(outport3)]
							self.add_flow(currentdatapath, 1, match4, actions4)
					 	
					else:
						
						currentdatapath = self.datapaths[path_list[0][i]]
						outport1 = self.net[path_list[0][i]][path_list[0][i+1]]['port']
						outport2 = self.net[path_list[0][i]][path_list[0][i-1]]['port']
						
						#andata mpls dfl
						match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, in_port=outport2)
						actions1 = [parser.OFPActionOutput(outport1)]
						self.add_flow(currentdatapath, 2, match1, actions1)
						
						#ritorno mpls dfl
						match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labeldfl, in_port=outport1)
						actions2 = [parser.OFPActionOutput(outport2)]
						self.add_flow(currentdatapath, 2, match2, actions2)
		
						
						currentdatapath = self.datapaths[path_list[1][i]]
						outport3 = self.net[path_list[1][i]][path_list[0][i+1]]['port']
						outport4 = self.net[path_list[1][i]][path_list[0][i-1]]['port']
						
						#andata mpls bu
						match3 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labelbu, in_port=outport4)
						actions3 = [parser.OFPActionOutput(outport3)]
						self.add_flow(currentdatapath, 1, match3, actions3)
						
						#ritorno mpls bu
						match4 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS, mpls_label=labelbu, in_port=outport3)
						actions4 = [parser.OFPActionOutput(outport4)]
						self.add_flow(currentdatapath, 1, match4, actions4)
			
					
	def assign_label(self):
		if not self.label_list:
			new_label = random.randint(1, 1000)
		else:
			new_label = random.randint(1, 1000)
			while new_label in self.label_list:
				new_label = random.randint(1, 1000)
		self.label_list.append(new_label)
		return new_label


	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):

		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]
		#print(switches)
		if self.GLOBAL_VARIABLE == 0:
			for s in switches:
				for switch_port in range(1, NUMBER_OF_SWITCH_PORTS+1):
					self.port_occupied.setdefault(s, {})
					# we suppose every port occupied (= 0)
					self.port_occupied[s][switch_port] = 0		
			#self.GLOBAL_VARIABLE = 1
		#print(self.port_occupied)
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
		# If there is a link attached to the port, then it is occupied (=1)
		for l in links_:
			self.port_occupied[l[0]][l[2]] = 1


app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')	
