from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from collections import defaultdict
import os

class SimpleSwitch13(app_manager.RyuApp):
    """Learning switch with traffic mirroring to Suricata IDS"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)
        self.suricata_port = {}  # Initialize suricata_port here!

    def _load_suricata_port(self):
        """Load Suricata port information from file"""
        try:
            if os.path.exists('/tmp/suricata_port.txt'):
                with open('/tmp/suricata_port.txt', 'r') as f:
                    content = f.read().strip()
                    dpid, port = content.split(',')
                    self.suricata_port[int(dpid)] = int(port)
                    self.logger.info("Loaded Suricata port: DPID=%s, Port=%s", dpid, port)
        except Exception as e:
            self.logger.error("Error loading Suricata port: %s", e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch connected: DPID=%s", datapath.id)
        
        # Load Suricata port configuration
        self._load_suricata_port()

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
                                            actions)]
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                   priority=priority, match=match,
                                   instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port')
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dpid = datapath.id
        src = eth.src
        dst = eth.dst
        
        # Don't process packets from Suricata to avoid loops
        if dpid in self.suricata_port and in_port == self.suricata_port[dpid]:
            return
        
        self.logger.info("packet in dpid=%s src=%s dst=%s in_port=%s", 
                        dpid, src, dst, in_port)
        
        # Learn the source MAC
        self.mac_to_port[dpid][src] = in_port
        
        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # Build actions list
        actions = [parser.OFPActionOutput(out_port)]
        
        # Mirror to Suricata ONLY on S1 (dpid=1)
        if dpid == 1 and dpid in self.suricata_port:
            suricata_port = self.suricata_port[dpid]
            if out_port != suricata_port:  # Don't mirror back to Suricata
                actions.append(parser.OFPActionOutput(suricata_port))
                self.logger.info("Mirroring to Suricata on port %s", suricata_port)
        
        # Install flow if we know the destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
