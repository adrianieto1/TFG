# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, tcp, udp, in_proto


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        #self.logger.info('Entra switchfeatures')

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
            self.logger.info(mod)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
            #self.logger.info(mod)
        datapath.send_msg(mod)

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
        #self.logger.info('Inicio PacketIn')

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        #self.logger.info("****************************************************************************************************************")
        #self.logger.info(out_port)
        #self.logger.info(ofproto.OFPP_FLOOD)
        #self.logger.info("****************************************************************************************************************")
        #import pdb; pdb.set_trace()
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                ipv4_src = ip.src
                ipv4_dst = ip.dst
                ip_proto = ip.proto
                if ip_proto == in_proto.IPPROTO_TCP:
                    tcp_src = pkt.get_protocol(tcp.tcp).src_port
                    tcp_dst = pkt.get_protocol(tcp.tcp).dst_port
                    match = parser.OFPMatch(eth_type = 0x800, in_port=in_port, eth_dst=dst, eth_src=src, tcp_dst=tcp_dst, tcp_src=tcp_src, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
                    #self.logger.info(match)
                    #self.logger.info('Match TCP')
                elif ip_proto == in_proto.IPPROTO_UDP:
                    udp_src = pkt.get_protocol(udp.udp).src_port
                    udp_dst = pkt.get_protocol(udp.udp).dst_port
                    match = parser.OFPMatch(eth_type = 0x800, in_port=in_port, eth_dst=dst, eth_src=src, udp_dst=udp_dst, udp_src=udp_src, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
                    #self.logger.info(match)
                elif ip_proto == in_proto.IPPROTO_ICMP:
                    ip_proto = 0
                    match = parser.OFPMatch(eth_type = 0x800, in_port=in_port, eth_dst=dst, eth_src=src, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
                    #self.logger.info(match)
            #else:
                #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, tcp_dst=0, tcp_src=0, udp_dst=0, udp_src=0, ipv4_dst=0, ipv4_src=0)
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, tcp_dst=tcp_dst, tcp_src=tcp_src, udp_dst=udp_dst, udp_src=udp_src, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #self.logger.info('PacketIn add flow 1')
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
                    #self.logger.info('PacketIn add flow 2')
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        #self.logger.info('PacketIn antes out')

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        #self.logger.info(out)
        #self.logger.info('PacketIn despois out')
        datapath.send_msg(out)
