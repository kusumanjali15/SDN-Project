from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp
from collections import defaultdict
import os
import threading
import json
import time
from datetime import datetime

class SimpleSwitch13(app_manager.RyuApp):
    """Learning switch with traffic mirroring to Suricata IDS and IP blocking"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)
        self.suricata_port = {}
        self.blocked_ips = set()
        self.blocked_ips_file = '/tmp/blocked_ips.txt'
        self.alert_file = '/tmp/eve.json'
        self.datapaths = {}
        self.alert_history = {}  # Track processed alerts: key=(sid, src_ip) -> last_seen_time
        self.alert_dedup_window = 60  # Seconds to suppress duplicate alerts for same SID+IP
        self.last_alert_position_file = '/tmp/alert_position.txt'
        self.dropped_packet_log = {}  # Track last log time per blocked IP to reduce spam
        self.dropped_log_interval = 5  # Only log dropped packets every N seconds per IP
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'alerts_processed': 0,
            'ips_blocked': 0
        }
        
        # Load configurations
        self._load_suricata_port()
        self._load_blocked_ips()
        
        # Start alert monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_alerts, daemon=True)
        self.monitor_thread.start()
        self.logger.info("=" * 60)
        self.logger.info("SDN-IDS Controller Started")
        self.logger.info("Alert monitoring thread started")
        self.logger.info("=" * 60)

    def _load_suricata_port(self):
        """Load Suricata port information from file"""
        max_retries = 10
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                if os.path.exists('/tmp/suricata_port.txt'):
                    with open('/tmp/suricata_port.txt', 'r') as f:
                        content = f.read().strip()
                        dpid, port = content.split(',')
                        self.suricata_port[int(dpid)] = int(port)
                        self.logger.info("✓ Loaded Suricata port: DPID=%s, Port=%s", dpid, port)
                        return
            except Exception as e:
                self.logger.debug("Waiting for Suricata port info (attempt %d/%d): %s", 
                                retry_count + 1, max_retries, e)
            
            retry_count += 1
            time.sleep(2)
        
        self.logger.warning("Could not load Suricata port configuration after %d attempts", max_retries)

    def _load_blocked_ips(self):
        """Load blocked IPs from file"""
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            self.blocked_ips.add(ip)
                self.logger.info("✓ Loaded %d blocked IPs from file", len(self.blocked_ips))
                self.stats['ips_blocked'] = len(self.blocked_ips)
        except Exception as e:
            self.logger.error("Error loading blocked IPs: %s", e)

    def _load_last_alert_position(self):
        """Load last processed position in alert file"""
        try:
            if os.path.exists(self.last_alert_position_file):
                with open(self.last_alert_position_file, 'r') as f:
                    return int(f.read().strip())
        except Exception:
            pass
        return 0
    
    def _save_last_alert_position(self, position):
        """Save last processed position in alert file"""
        try:
            with open(self.last_alert_position_file, 'w') as f:
                f.write(str(position))
        except Exception as e:
            self.logger.debug("Could not save alert position: %s", e)

    def _monitor_alerts(self):
        """Background thread that monitors Suricata alert file"""
        self.logger.info("Alert monitor ready - watching: %s", self.alert_file)
        
        # Load last position - skip already processed alerts on restart
        last_position = self._load_last_alert_position()
        if last_position > 0:
            self.logger.info("Resuming alert monitoring from position %d", last_position)
        
        last_check = time.time()
        incomplete_line = ""  # Buffer for incomplete JSON lines
        
        while True:
            try:
                current_time = time.time()
                
                # Log heartbeat every 30 seconds
                if current_time - last_check > 30:
                    self.logger.debug("Alert monitor active - Stats: %s", self.stats)
                    last_check = current_time
                
                # Clean up old entries from alert_history (older than dedup window)
                self._cleanup_alert_history(current_time)
                
                if os.path.exists(self.alert_file):
                    file_size = os.path.getsize(self.alert_file)
                    
                    if file_size > last_position:
                        with open(self.alert_file, 'r') as f:
                            f.seek(last_position)
                            content = f.read()
                            
                            # Combine with any incomplete line from previous read
                            content = incomplete_line + content
                            incomplete_line = ""
                            
                            lines = content.split('\n')
                            
                            # If content doesn't end with newline, last line may be incomplete
                            if not content.endswith('\n') and lines:
                                incomplete_line = lines[-1]
                                lines = lines[:-1]
                            
                            for line in lines:
                                line = line.strip()
                                if line:
                                    try:
                                        alert_data = json.loads(line)
                                        if alert_data.get('event_type') == 'alert':
                                            self._process_alert(alert_data)
                                    except json.JSONDecodeError:
                                        # Silently skip malformed lines
                                        pass
                            
                            # Update position (minus incomplete line length)
                            last_position = f.tell() - len(incomplete_line.encode('utf-8'))
                            if not incomplete_line:  # Only save if we processed complete lines
                                self._save_last_alert_position(last_position)
                    
                    elif file_size < last_position:
                        self.logger.info("Alert file was rotated, resetting position")
                        last_position = 0
                        incomplete_line = ""
                        self._save_last_alert_position(0)
                
                time.sleep(0.5)  # Check twice per second for faster response
                
            except Exception as e:
                self.logger.error("Error monitoring alerts: %s", e)
                time.sleep(5)
    
    def _cleanup_alert_history(self, current_time):
        """Remove old entries from alert history"""
        expired_keys = [key for key, timestamp in self.alert_history.items() 
                       if current_time - timestamp > self.alert_dedup_window * 2]
        for key in expired_keys:
            del self.alert_history[key]

    def _process_alert(self, alert_data):
        """Process a single Suricata alert and block IPs if necessary"""
        try:
            alert = alert_data.get('alert', {})
            severity = alert.get('severity', 3)
            src_ip = alert_data.get('src_ip')
            dst_ip = alert_data.get('dest_ip')
            signature = alert.get('signature', 'Unknown')
            sid = alert.get('signature_id', 0)
            timestamp = alert_data.get('timestamp', '')
            current_time = time.time()
            
            # EARLY EXIT: Skip alerts for already-blocked IPs (no logging spam)
            if src_ip in self.blocked_ips:
                self.logger.debug("Ignoring alert for already-blocked IP: %s (SID: %s)", src_ip, sid)
                return
            
            # Deduplication: Check if we've seen this SID+IP combination recently
            alert_key = (sid, src_ip)
            if alert_key in self.alert_history:
                last_seen = self.alert_history[alert_key]
                if current_time - last_seen < self.alert_dedup_window:
                    self.logger.debug("Suppressing duplicate alert SID=%s for %s (seen %.1fs ago)", 
                                     sid, src_ip, current_time - last_seen)
                    return
            
            # Record this alert in history
            self.alert_history[alert_key] = current_time
            self.stats['alerts_processed'] += 1
            
            self.logger.info("=" * 60)
            self.logger.info("ALERT DETECTED")
            self.logger.info("  SID: %s", sid)
            self.logger.info("  Severity: %s", severity)
            self.logger.info("  Signature: %s", signature)
            self.logger.info("  Source IP: %s", src_ip)
            self.logger.info("  Dest IP: %s", dst_ip)
            self.logger.info("  Timestamp: %s", timestamp)
            self.logger.info("=" * 60)
            
            # Block high-priority threats (severity 1-2)
            if severity in [1, 2] and src_ip:
                self.logger.warning("🚨 HIGH PRIORITY ALERT (Severity %s) - BLOCKING IP: %s", 
                                  severity, src_ip)
                self._block_ip_all_switches(src_ip, signature)
            
        except Exception as e:
            self.logger.error("Error processing alert: %s", e)

    def _block_ip_all_switches(self, ip_address, reason="Security threat"):
        """Block an IP address on all connected switches"""
        if ip_address in self.blocked_ips:
            self.logger.debug("IP %s is already blocked", ip_address)
            return
        
        self.blocked_ips.add(ip_address)
        self._save_blocked_ips()
        self.stats['ips_blocked'] = len(self.blocked_ips)
        
        blocked_count = 0
        for dpid, datapath in self.datapaths.items():
            try:
                self._install_ip_block_rules(datapath, ip_address)
                blocked_count += 1
            except Exception as e:
                self.logger.error("Failed to block IP %s on DPID=%s: %s", 
                                ip_address, dpid, e)
        
        self.logger.warning("=" * 60)
        self.logger.warning("🔒 IP BLOCKED: %s", ip_address)
        self.logger.warning("   Reason: %s", reason)
        self.logger.warning("   Applied to: %d switches", blocked_count)
        self.logger.warning("   Total blocked IPs: %d", len(self.blocked_ips))
        self.logger.warning("=" * 60)

    def _install_ip_block_rules(self, datapath, ip_address):
        """Install blocking flow rules for a specific IP on a switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # CRITICAL: Use high priority (200) to override learning flows
        priority = 200
        
        # Block packets FROM this IP (source)
        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        actions = []  # Empty actions = drop
        self.add_flow(datapath, priority, match_src, actions)
        
        # Block packets TO this IP (destination)
        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_address)
        self.add_flow(datapath, priority, match_dst, actions)
        
        self.logger.info("  ✓ Installed block rules for %s on DPID=%s (priority=%d)", 
                       ip_address, datapath.id, priority)

    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                f.write(f"# Blocked IPs - Updated: {datetime.now()}\n")
                for ip in sorted(self.blocked_ips):
                    f.write(ip + '\n')
            self.logger.debug("Saved %d blocked IPs to file", len(self.blocked_ips))
        except Exception as e:
            self.logger.error("Error saving blocked IPs: %s", e)

    def _install_block_rules(self, datapath):
        """Install blocking rules for all blocked IPs on a switch"""
        for ip in self.blocked_ips:
            self._install_ip_block_rules(datapath, ip)
        
        if self.blocked_ips:
            self.logger.info("  ✓ Installed blocking rules for %d IPs on DPID=%s", 
                           len(self.blocked_ips), datapath.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Store datapath for later use
        self.datapaths[datapath.id] = datapath
        
        self.logger.info("=" * 60)
        self.logger.info("SWITCH CONNECTED: DPID=%s", datapath.id)
        
        # Install table-miss flow entry (lowest priority)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("  ✓ Installed table-miss flow entry")
        
        # Install IP blocking rules (high priority)
        self._install_block_rules(datapath)
        
        # Log Suricata configuration for this switch
        if datapath.id in self.suricata_port:
            self.logger.info("  ✓ Suricata mirror port: %s", self.suricata_port[datapath.id])
        
        self.logger.info("=" * 60)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Handle switch disconnection"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Switch registered: DPID=%s", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.warning("Switch disconnected: DPID=%s", datapath.id)
                del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0, log_flow=True):
        """Add a flow entry to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath, 
                buffer_id=buffer_id,
                priority=priority, 
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, 
                priority=priority,
                match=match, 
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)
        
        # Log flow installation only for IPv4 packets (or blocking rules)
        if log_flow:
            action_str = "DROP" if not actions else ", ".join([str(a) for a in actions])
            self.logger.info("[FLOW] DPID=%s priority=%d actions=[%s]",
                            datapath.id, priority, action_str)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match.get('in_port')
            
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
        except Exception as e:
            self.logger.error("Error in packet_in (parsing): %s", e, exc_info=True)
            return
        
        # Ignore LLDP and IPv6 (silently)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        
        dpid = datapath.id
        src = eth.src
        dst = eth.dst
        
        self.stats['packets_processed'] += 1
        
        # Check if packet is IPv4 and check for blocked IPs
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # Drop packets from or to blocked IPs (with rate-limited logging)
            current_time = time.time()
            if src_ip in self.blocked_ips:
                self.stats['packets_blocked'] += 1
                # Only log occasionally to avoid spam
                if src_ip not in self.dropped_packet_log or \
                   current_time - self.dropped_packet_log[src_ip] > self.dropped_log_interval:
                    self.logger.warning("⛔ Dropping packets from blocked IP: %s (count: %d)", 
                                       src_ip, self.stats['packets_blocked'])
                    self.dropped_packet_log[src_ip] = current_time
                return
            if dst_ip in self.blocked_ips:
                self.stats['packets_blocked'] += 1
                if dst_ip not in self.dropped_packet_log or \
                   current_time - self.dropped_packet_log[dst_ip] > self.dropped_log_interval:
                    self.logger.warning("⛔ Dropping packets to blocked IP: %s (count: %d)", 
                                       dst_ip, self.stats['packets_blocked'])
                    self.dropped_packet_log[dst_ip] = current_time
                return
            
            # Log IPv4 packets with IP addresses (only non-blocked traffic)
            self.logger.debug("[IPv4] DPID=%s %s → %s (MAC: %s → %s)",
                           dpid, src_ip, dst_ip, src, dst)
        
        # Don't process packets from Suricata to avoid loops
        if dpid in self.suricata_port and in_port == self.suricata_port[dpid]:
            return
        
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
            if out_port != suricata_port and in_port != suricata_port:
                actions.append(parser.OFPActionOutput(suricata_port))
        
        # Install flow if we know the destination (priority 10, above table-miss but below blocking)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # Only log LEARN for IPv4 packets (cleaner output)
            if ip_pkt:
                mirror_info = " +mirror" if (dpid == 1 and dpid in self.suricata_port) else ""
                self.logger.info("[LEARN] DPID=%s %s → %s port %s→%s%s",
                               dpid, ip_pkt.src, ip_pkt.dst, in_port, out_port, mirror_info)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id, idle_timeout=30, log_flow=ip_pkt is not None)
                return
            else:
                self.add_flow(datapath, 10, match, actions, idle_timeout=30, log_flow=ip_pkt is not None)
        
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=msg.buffer_id,
            in_port=in_port, 
            actions=actions, 
            data=data
        )
        datapath.send_msg(out)
