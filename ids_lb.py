# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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


import array

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.controller import dpset


class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'snortlib': snortlib.SnortLib,
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.dpset = kwargs['dpset']
        self.snort_port = 47
        self.mac_to_port = {}

        socket_config = {'unixsock': True}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if eth:
            self.logger.info("%r", eth)
        if _ipv4:
            self.logger.info("%r", _ipv4)
        if _icmp:
            self.logger.info("%r", _icmp)
        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print 'p:', p.protocol_name

    def packet_drop(self, pkt, datapath, parser):
        pkt = packet.Packet(array.array('B', pkt))
        _ipv4 = pkt.get_protocol(ipv4.ipv4)

        drop_actions = []

        if _ipv4:
            block_dst = _ipv4.dst
            block_src = _ipv4.src

            bot_match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                        ip_proto=inet.IPPROTO_ICMP,
                                        ipv4_dst=block_dst,
                                        ipv4_src=block_src)

            self.add_flow(datapath, 10, bot_match, drop_actions)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        datapath = self.dpset.get(6357814281)
        parser = datapath.ofproto_parser
        alert = ''.join(msg.alertmsg)

        if alert:
            # self.packet_print(msg.pkt)
            self.logger.info('alertmsg:%s', alert)
            self.packet_drop(msg.pkt, datapath, parser)

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
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        l2_learning_actions = [parser.OFPActionOutput(out_port)]
        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]
        # actions = [parser.OFPActionOutput(out_port),
        #            parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, l2_learning_actions)

            # Detect Botnet infected via IRC channel
            match_irc_out = parser.OFPMatch(in_port=in_port,
                                            eth_type=ether.ETH_TYPE_IP,
                                            ip_proto=inet.IPPROTO_TCP,
                                            tcp_dst=6667)

            match_irc_in = parser.OFPMatch(in_port=in_port,
                                           eth_type=ether.ETH_TYPE_IP,
                                           ip_proto=inet.IPPROTO_TCP,
                                           tcp_src=6667)

            self.add_flow(datapath, 10, match_irc_out, actions)
            self.add_flow(datapath, 10, match_irc_in, actions)

        # For packet-out
        actions = l2_learning_actions
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
