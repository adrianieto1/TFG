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
from datetime import datetime
from ryu.lib import hub
import joblib
from prettytable import PrettyTable 
import numpy as np 
import pandas as pd
import sys, subprocess
#from ryu.ofproto import ofproto_v1_3


class Flow:
    def __init__(self,TotLen_Bwd_Pkts,Fwd_Pkt_Len_Max,Fwd_Pkt_Len_Min,Fwd_Pkt_Len_Std,Bwd_Pkt_Len_Min,Bwd_Pkt_Len_Std,Flow_Byts_s,Flow_Pkts_s,Flow_IAT_Mean,Flow_IAT_Min,Fwd_IAT_Std,Bwd_IAT_Tot,Bwd_IAT_Std,Bwd_IAT_Max,Bwd_Header_Len,Pkt_Len_Max,Pkt_Len_Mean,Pkt_Len_Std,Pkt_Len_Var,Down_Up_Ratio,Fwd_Seg_Size_Avg,Bwd_Seg_Size_Avg,Init_Bwd_Win_Byts,Active_Min,Idle_Std,Puerto_Origen,Puerto_Destino,IP_Origen,IP_Destino,Seno_Hora,Coseno_Hora):
        self.TotLen_Bwd_Pkts =   TotLen_Bwd_Pkts
        self.Fwd_Pkt_Len_Max =   Fwd_Pkt_Len_Max
        self.Fwd_Pkt_Len_Min =   Fwd_Pkt_Len_Min
        self.Fwd_Pkt_Len_Std =   Fwd_Pkt_Len_Std
        self.Bwd_Pkt_Len_Min =   Bwd_Pkt_Len_Min
        self.Bwd_Pkt_Len_Std =   Bwd_Pkt_Len_Std
        self.Flow_Byts_s =       Flow_Byts_s
        self.Flow_Pkts_s =       Flow_Pkts_s
        self.Flow_IAT_Mean =     Flow_IAT_Mean
        self.Flow_IAT_Min =      Flow_IAT_Min
        self.Fwd_IAT_Std =       Fwd_IAT_Std
        self.Bwd_IAT_Tot =       Bwd_IAT_Tot
        self.Bwd_IAT_Std =       Bwd_IAT_Std
        self.Bwd_IAT_Max =       Bwd_IAT_Max
        self.Bwd_Header_Len =    Bwd_Header_Len
        self.Pkt_Len_Max =       Pkt_Len_Max
        self.Pkt_Len_Mean =      Pkt_Len_Mean
        self.Pkt_Len_Std =       Pkt_Len_Std
        self.Pkt_Len_Var =       Pkt_Len_Var
        self.Down_Up_Ratio =     Down_Up_Ratio
        self.Fwd_Seg_Size_Avg =  Fwd_Seg_Size_Avg
        self.Bwd_Seg_Size_Avg =  Bwd_Seg_Size_Avg
        self.Init_Bwd_Win_Byts = Init_Bwd_Win_Byts
        self.Active_Min =        Active_Min
        self.Idle_Std =          Idle_Std
        self.Puerto_Origen =     Puerto_Origen
        self.Puerto_Destino =    Puerto_Destino
        self.IP_Origen =         IP_Origen
        self.IP_Destino=         IP_Destino
        self.Seno_Hora =         Seno_Hora
        self.Coseno_Hora =       Coseno_Hora


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flows = {}
        self.rep = {}
        self.datos = pd.read_csv('datos.csv', header=0)
        self.datos = self.datos.drop(self.datos.columns[0],axis='columns')
        self.previo_id = '0'

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


    def mod_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
            #self.logger.info(mod)
        datapath.send_msg(mod)


    def _run_ryu(self,datapath,tcp_src,tcp_dst,udp_src,udp_dst,ipv4_src,ipv4_dst,ip_proto):
        time = 0
        while True:
            unique_id = '0'
            reverse_id = '0'

            if ip_proto == 6:
                unique_id = '-'.join([ipv4_dst,ipv4_src,str(tcp_dst),str(tcp_src),str(ip_proto)])  #create unique ID for flow based on switch ID, source host,and destination host
                reverse_id = '-'.join([ipv4_src,ipv4_dst,str(tcp_src),str(tcp_dst),str(ip_proto)])
            elif ip_proto == 17:
                unique_id = '-'.join([ipv4_dst,ipv4_src,str(udp_dst),str(udp_src),str(ip_proto)]) #create unique ID for flow based on switch ID, source host,and destination host
                reverse_id = '-'.join([ipv4_src,ipv4_dst,str(udp_src),str(udp_dst),str(ip_proto)])
            else:
                unique_id = '-'.join([ipv4_dst,ipv4_src,'0-0',str(ip_proto)]) #create unique ID for flow based on switch ID, source host,and destination host
                reverse_id = '-'.join([ipv4_src,ipv4_dst,'0-0',str(ip_proto)])

            #print(unique_id)
            #print(reverse_id)
            if unique_id != self.previo_id:
                self.previo_id = unique_id
                if (self.datos.isin([unique_id]).any().any()) or (self.datos.isin([reverse_id]).any().any()):
                    print('papas')
                    if unique_id not in self.rep:
                        self.rep[unique_id] = 1
                        filauni = self.datos.loc[self.datos['Flow ID']==unique_id]
                        filarev = self.datos.loc[self.datos['Flow ID']==reverse_id]
                        fila = pd.concat([filauni,filarev])
                        fila = fila.iloc[0]
                        self.flows[unique_id] = Flow(fila['TotLen Bwd Pkts'],fila['Fwd Pkt Len Max'],fila['Fwd Pkt Len Min'],fila['Fwd Pkt Len Std'],fila['Bwd Pkt Len Min'],fila['Bwd Pkt Len Std'],fila['Flow Byts/s'],fila['Flow Pkts/s'],fila['Flow IAT Mean'],fila['Flow IAT Min'],fila['Fwd IAT Std'],fila['Bwd IAT Tot'],fila['Bwd IAT Std'],fila['Bwd IAT Max'],fila['Bwd Header Len'],fila['Pkt Len Max'],fila['Pkt Len Mean'],fila['Pkt Len Std'],fila['Pkt Len Var'],fila['Down/Up Ratio'],fila['Fwd Seg Size Avg'],fila['Bwd Seg Size Avg'],fila['Init Bwd Win Byts'],fila['Active Min'],fila['Idle Std'],fila['Puerto Origen'],fila['Puerto Destino'],fila['IP Origen'],fila['IP Destino'],fila['Seno Hora'],fila['Coseno Hora'])
                    elif self.rep[unique_id] >= 1:
                        filauni = self.datos.loc[self.datos['Flow ID']==unique_id]
                        filarev = self.datos.loc[self.datos['Flow ID']==reverse_id]
                        fila = pd.concat([filauni,filarev])
                        fila = fila.iloc[self.rep[unique_id]]
                        self.flows[unique_id] = Flow(fila['TotLen Bwd Pkts'],fila['Fwd Pkt Len Max'],fila['Fwd Pkt Len Min'],fila['Fwd Pkt Len Std'],fila['Bwd Pkt Len Min'],fila['Bwd Pkt Len Std'],fila['Flow Byts/s'],fila['Flow Pkts/s'],fila['Flow IAT Mean'],fila['Flow IAT Min'],fila['Fwd IAT Std'],fila['Bwd IAT Tot'],fila['Bwd IAT Std'],fila['Bwd IAT Max'],fila['Bwd Header Len'],fila['Pkt Len Max'],fila['Pkt Len Mean'],fila['Pkt Len Std'],fila['Pkt Len Var'],fila['Down/Up Ratio'],fila['Fwd Seg Size Avg'],fila['Bwd Seg Size Avg'],fila['Init Bwd Win Byts'],fila['Active Min'],fila['Idle Std'],fila['Puerto Origen'],fila['Puerto Destino'],fila['IP Origen'],fila['IP Destino'],fila['Seno Hora'],fila['Coseno Hora'])
                        self.rep[unique_id] = self.rep[unique_id] + 1
                    modelo = joblib.load('modelorf.joblib')
                    x = PrettyTable()
                    x.field_names = ["Flow ID", "IP Origen", "IP Destino", "Puerto Origen","Puerto Destino","Tipo"]

                    for key,flow in self.flows.items():
                        features = np.asarray([flow.TotLen_Bwd_Pkts,flow.Fwd_Pkt_Len_Max,flow.Fwd_Pkt_Len_Min,flow.Fwd_Pkt_Len_Std,flow.Bwd_Pkt_Len_Min,flow.Bwd_Pkt_Len_Std,flow.Flow_Byts_s,flow.Flow_Pkts_s,flow.Flow_IAT_Mean,flow.Flow_IAT_Min,flow.Fwd_IAT_Std,flow.Bwd_IAT_Tot,flow.Bwd_IAT_Std,flow.Bwd_IAT_Max,flow.Bwd_Header_Len,flow.Pkt_Len_Max,flow.Pkt_Len_Mean,flow.Pkt_Len_Std,flow.Pkt_Len_Var,flow.Down_Up_Ratio,flow.Fwd_Seg_Size_Avg,flow.Bwd_Seg_Size_Avg,flow.Init_Bwd_Win_Byts,flow.Active_Min,flow.Idle_Std,flow.Puerto_Origen,flow.Puerto_Destino,flow.IP_Origen,flow.IP_Destino,flow.Seno_Hora,flow.Coseno_Hora]).reshape(1,-1) #convert to array so the model can understand the features properly
        
                        label = modelo.predict(features.tolist()) #if model is supervised (logistic regression) then the label is the type of traffic
        
                        #if the model is unsupervised, the label is a cluster number. Refer to Jupyter notebook to see how cluster numbers map to labels
                        if label == 0: 
                            label = ['Normal']
                        elif label == 1: 
                            label = ['Ataque']

                        if ip_proto == 17:
                                src_port = udp_src
                                dst_port = udp_dst
                        else:
                            src_port = tcp_src
                            dst_port = tcp_dst
                        x.add_row([key,ipv4_src,ipv4_dst,src_port,dst_port,label[0]]) 
                        print(x)#print output in pretty mode (i.e. formatted table) 
                        #if the model is unsupervised, the label is a cluster number. Refer to Jupyter notebook to see how cluster numbers map to labels
                        if label == ['Normal']: 
                            return(0)
                        elif label == ['Ataque']: 
                            return(1)
                #else:
                    #return
            #else:
                #flows[unique_id] = Flow(fila['TotLen Bwd Pkts'],fila['Fwd Pkt Len Max'],fila['Fwd Pkt Len Min'],fila['Fwd Pkt Len Std'],fila['Bwd Pkt Len Min'],fila['Bwd Pkt Len Std'],fila['Flow Byts/s'],fila['Flow Pkts/s'],fila['Flow IAT Mean'],fila['Flow IAT Min'],fila['Fwd IAT Std'],fila['Bwd IAT Tot'],fila['Bwd IAT Std'],fila['Bwd IAT Max'],fila['Bwd Header Len'],fila['Pkt Len Max'],fila['Pkt Len Mean'],fila['Pkt Len Std'],fila['Pkt Len Var'],fila['Down Up Ratio'],fila['Fwd Seg Size Avg'],fila['Bwd Seg Size Avg'],fila['Init Bwd Win Byts'],fila['Active Min'],fila['Idle Std'],fila['Puerto Origen'],fila['Puerto Destino'],fila['IP Origen'],fila['IP Destino'],fila['Seno Hora'],fila['Coseno Hora'])
            #if unique_id in flows.keys():
                #flows[unique_id].updateforward(int(fields[6]),int(fields[7]),int(fields[0])) #update forward attributes with time, packet, and byte count
            #else:
                # rev_unique_id = hash(''.join([fields[1],fields[4],fields[3]])) #switch source and destination to generate same hash for src/dst and dst/src
                #if rev_unique_id in flows.keys():
                    #flows[rev_unique_id].updatereverse(int(fields[6]),int(fields[7]),int(fields[0])) #update reverse attributes with time, packet, and byte count
                #else:
                    #flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]), int(fields[7])) #create new flow object
            #if time%10==0:
            else:
                return
            if unique_id == self.previo_id:
                return
            #time += 1

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
                    udp_src = 0
                    udp_dst = 0
                    match = parser.OFPMatch(eth_type = 0x800, in_port=in_port, eth_dst=dst, eth_src=src, tcp_src=tcp_src, tcp_dst=tcp_dst, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
                    #self.logger.info(match)
                    #self.logger.info('Match TCP')
                elif ip_proto == in_proto.IPPROTO_UDP:
                    udp_src = pkt.get_protocol(udp.udp).src_port
                    udp_dst = pkt.get_protocol(udp.udp).dst_port
                    tcp_src = 0
                    tcp_dst = 0
                    match = parser.OFPMatch(eth_type = 0x800, in_port=in_port, eth_dst=dst, eth_src=src, udp_src=udp_src, udp_dst=udp_dst, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
                    #self.logger.info(match)
                elif ip_proto == in_proto.IPPROTO_ICMP:
                    ip_proto = 0
                    tcp_src = 0
                    tcp_dst = 0
                    udp_src = 0
                    udp_dst = 0
                    match = parser.OFPMatch(eth_type = 0x800, in_port=in_port, eth_dst=dst, eth_src=src, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
                    #self.logger.info(match)
            #else:
                #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, tcp_dst=tcp_dst, tcp_src=tcp_src, udp_dst=udp_dst, udp_src=udp_src, ipv4_dst=ipv4_dst, ipv4_src=ipv4_src, ip_proto=ip_proto)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #self.logger.info('PacketIn add flow 1')
                    return
                else:
                    print('papas')
                    self.add_flow(datapath, 1, match, actions)
                    #self.logger.info('PacketIn add flow 2')

                if(self._run_ryu(datapath,tcp_src,tcp_dst,udp_src,udp_dst,ipv4_src,ipv4_dst,ip_proto)==1):
                    print('Ataque')
                    self.mod_flow(datapath,1,match)
                else:
                    print('Normal')

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        #self.logger.info('PacketIn antes out')

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        #self.logger.info(out)
        #self.logger.info('PacketIn despois out')
        datapath.send_msg(out)



