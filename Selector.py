from switch_firewall import *
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from operator import attrgetter
from datetime import datetime
from ryu.lib import hub
from ryu.app import simple_switch_13
from ryu.lib.packet import packet, ipv4, tcp, udp, in_proto
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

class SimpleMonitor13(SimpleSwitch13):
#class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    #OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) :
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.fields = {'time':'','datapath':'','tcp_src':'','tcp_dst':'','udp_src':'','udp_dst':'','ipv4_src':'','ipv4_dst':'','ip_proto':''}
        self.flows = {}
        self.rep = {}
        self.datos = pd.read_csv('datos.csv', header=0)
        self.datos = self.datos.drop(self.datos.columns[0],axis='columns')
        self.previo_id = '0'

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def flow_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        self.logger.info('time\tdatapath\ttcp_src\ttcp_dst\tudp_src\tudp_dst\tipv4_src\tipv4_dst\tip_proto')
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

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

    def _printclassifier(self,datapath,match,model):
        x = PrettyTable()
        x.field_names = ["Flow ID", "IP Origen", "IP Destino", "Puerto Origen","Puerto Destino","Tipo"]

        for key,flow in self.flows.items():
            features = np.asarray([flow.TotLen_Bwd_Pkts,flow.Fwd_Pkt_Len_Max,flow.Fwd_Pkt_Len_Min,flow.Fwd_Pkt_Len_Std,flow.Bwd_Pkt_Len_Min,flow.Bwd_Pkt_Len_Std,flow.Flow_Byts_s,flow.Flow_Pkts_s,flow.Flow_IAT_Mean,flow.Flow_IAT_Min,flow.Fwd_IAT_Std,flow.Bwd_IAT_Tot,flow.Bwd_IAT_Std,flow.Bwd_IAT_Max,flow.Bwd_Header_Len,flow.Pkt_Len_Max,flow.Pkt_Len_Mean,flow.Pkt_Len_Std,flow.Pkt_Len_Var,flow.Down_Up_Ratio,flow.Fwd_Seg_Size_Avg,flow.Bwd_Seg_Size_Avg,flow.Init_Bwd_Win_Byts,flow.Active_Min,flow.Idle_Std,flow.Puerto_Origen,flow.Puerto_Destino,flow.IP_Origen,flow.IP_Destino,flow.Seno_Hora,flow.Coseno_Hora]).reshape(1,-1) #convert to array so the model can understand the features properly
        
            label = model.predict(features.tolist()) #if model is supervised (logistic regression) then the label is the type of traffic
        
            #if the model is unsupervised, the label is a cluster number. Refer to Jupyter notebook to see how cluster numbers map to labels
            if label == 0: 
                label = ['Normal']
            elif label == 1: 
                label = ['Ataque']
                self.mod_flow(datapath,1,match)

            if self.fields['ip_proto'] == 17:
                src_port = self.fields['udp_src']
                dst_port = self.fields['udp_dst']
            else:
                src_port = self.fields['tcp_src']
                dst_port = self.fields['tcp_dst']
            x.add_row([key, self.fields['ipv4_src'], self.fields['ipv4_dst'],src_port,dst_port,label[0]]) 
            print(x)#print output in pretty mode (i.e. formatted table)


    def _run_ryu(self,datapath,match,tcp_src,tcp_dst,udp_src,udp_dst,ipv4_src,ipv4_dst,ip_proto):
        time = 0
        while True:
            unique_id = '0'
            reverse_id = '0'
            no_data = 0

            if ip_proto == 6:
                unique_id = '-'.join([ipv4_dst,ipv4_src,str(tcp_dst),str(tcp_src),str(ip_proto)])  #create unique ID for flow based on switch ID, source host,and destination host
                reverse_id = '-'.join([ipv4_src,ipv4_dst,str(tcp_src),str(tcp_dst),str(ip_proto)])
            elif ip_proto == 17:
                unique_id = '-'.join([ipv4_dst,ipv4_src,str(udp_dst),str(udp_src),str(ip_proto)]) #create unique ID for flow based on switch ID, source host,and destination host
                reverse_id = '-'.join([ipv4_src,ipv4_dst,str(udp_src),str(udp_dst),str(ip_proto)])
            else:
                unique_id = '-'.join([ipv4_dst,ipv4_src,'0-0',str(ip_proto)]) #create unique ID for flow based on switch ID, source host,and destination host
                reverse_id = '-'.join([ipv4_src,ipv4_dst,'0-0',str(ip_proto)])
            
            if unique_id != self.previo_id:
                self.previo_id = unique_id
                if (self.datos.isin([unique_id]).any().any()) or (self.datos.isin([reverse_id]).any().any()):
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
                    modelo = joblib.load('modelolr.joblib')
                    self._printclassifier(datapath,match,modelo)
                else:
                    return
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
            if unique_id == self.previo_id:
                return
            #time += 1

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        #self.logger.info(body)
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            #self.logger.info(stat.match['ip_proto'])
            #print details of flows

            self.fields['time'] = datetime.utcnow().strftime('%s')
            self.fields['datapath'] = ev.msg.datapath.id
            if(stat.match['ip_proto'] == 6):
                self.fields['udp_src'] = 0
                self.fields['udp_dst'] = 0
                self.fields['tcp_src'] = stat.match['tcp_src']
                self.fields['tcp_dst'] = stat.match['tcp_dst']
            elif(stat.match['ip_proto'] == 17):
                self.fields['tcp_src'] = 0
                self.fields['tcp_dst'] = 0
                self.fields['udp_src'] = stat.match['udp_src']
                self.fields['udp_dst'] = stat.match['udp_dst']
            else:
                self.fields['tcp_src'] = 0
                self.fields['tcp_dst'] = 0
                self.fields['udp_src'] = 0
                self.fields['udp_dst'] = 0
            self.fields['ipv4_src'] = stat.match['ipv4_src']
            self.fields['ipv4_dst'] = stat.match['ipv4_dst']
            self.fields['ip_proto'] = stat.match['ip_proto']

            #self.logger.info('data\t%s\t%x\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t',self.fields['time'],self.fields['datapath'],self.fields['tcp_src'],self.fields['tcp_dst'],self.fields['udp_src'],self.fields['udp_dst'],self.fields['ipv4_src'],self.fields['ipv4_dst'],self.fields['ip_proto'])
            self._run_ryu(datapath,stat.match,self.fields['tcp_src'], self.fields['tcp_dst'], self.fields['udp_src'], self.fields['udp_dst'], self.fields['ipv4_src'], self.fields['ipv4_dst'], self.fields['ip_proto'])

