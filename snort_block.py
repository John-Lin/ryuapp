import array
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet, ether
from ryu.lib.packet import arp, packet, icmp, ipv4
from ryu.lib import snortlib
from ryu.controller import dpset


class Normal(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'snortlib': snortlib.SnortLib,
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(Normal, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.dpset = kwargs['dpset']
        self.snort_port = 38

        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        self.add_flow(datapath, 1, 0, match, actions_normal)
        self.mirror(datapath, 0, match)

    def add_flow(self, datapath, table_id, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                priority=priority, match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def mirror(self, datapath, priority, match_pattern):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions_mirror = [parser.OFPActionOutput(self.snort_port)]

        inst = [parser.OFPInstructionGotoTable(1),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions_mirror)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match_pattern, instructions=inst)
        datapath.send_msg(mod)

    def block_flow(self, datapath, priority, pkt):
        parser = datapath.ofproto_parser
        pkt = packet.Packet(array.array('B', pkt))
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        drop_actions = []

        if _ipv4:
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=_ipv4.src)

        self.add_flow(datapath, 1, 10, match, drop_actions)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        alert = ''.join(msg.alertmsg)

        self.logger.info('alertmsg:%s', alert)
        # TODO
        # 1. When there is snort alert save to Database
        # 2. Get snort machine loading
        # 3. Drop the Bad flow

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        pass
        # msg = ev.msg
        # datapath = msg.datapath
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        # in_port = msg.match['in_port']

        # pkt = packet.Packet(msg.data)
        # pkt_arp = pkt.get_protocol(arp.arp)
        # pkt_icmp = pkt.get_protocol(icmp.icmp)
