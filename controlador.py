from ryu.app import simple_switch_13
from ryu.ofproto import ofproto_v1_6
from ryu.controller import ofp_event
from ry.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from operator import attrgetter
from datetime import datetime
from ryu.lib import hub

class AppSwitch(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_6.OFP_VERSION]

    def __init__(self, *args, **kwargs) :
        super(AppSwitch, self).__init__(*args, **kwargs)
        self.datapaths = {}

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
        self.logger.info('time\tdatapath\tin-port\teth-src\teth-dst\tout-port\ttotal_packets\ttotal_bytes')
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

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            #print details of flows
            self.fields['time'] = datetime.utcnow().strftime('%s')
            self.fields['datapath'] = ev.msg.datapath.id
            self.fields['in-port'] = stat.match['in_port']
            self.fields['eth_src'] = stat.match['eth_src']
            self.fields['eth_dst'] = stat.match['eth_dst']
            self.fields['out-port'] = stat.instructions[0].actions[0].port
            self.fields['total_packets'] = stat.packet_count
            self.fields['total_bytes'] = stat.byte_count

            self.logger.info('data\t%s\t%x\t%x\t%s\t%s\t%x\t%d\t%d',self.fields['time'],self.fields['datapath'],self.fields['in-port'],self.fields['eth_src'],self.fields['eth_dst'],self.fields['out-port'],self.fields['total_packets'],self.fields['total_bytes'])
