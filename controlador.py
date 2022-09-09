from simple_switch_mod import *
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from operator import attrgetter
from datetime import datetime
from ryu.lib import hub
from ryu.app import simple_switch_13
from ryu.lib.packet import packet, ipv4, tcp, udp, in_proto
#from ryu.ofproto import ofproto_v1_3

class SimpleMonitor13(SimpleSwitch13):
#class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    #OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) :
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.fields = {'time':'','datapath':'','tcp_src':'','tcp_dst':'','udp_src':'','udp_dst':'','ipv4_src':'','ipv4_dst':'','ip_proto':''}

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

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        #self.logger.info('FlowStatsReply controlador')
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
            self.logger.info('data\t%s\t%x\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t',self.fields['time'],self.fields['datapath'],self.fields['tcp_src'],self.fields['tcp_dst'],self.fields['udp_src'],self.fields['udp_dst'],self.fields['ipv4_src'],self.fields['ipv4_dst'],self.fields['ip_proto'])
