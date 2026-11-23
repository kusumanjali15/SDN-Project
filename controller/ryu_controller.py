from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, tcp, udp
from collections import defaultdict
import os
import sys
import warnings
import threading
import json
import time
from datetime import datetime

# Add ML module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings
from controller.enforcement import (
    PersistenceTracker, BlockRecord, block_timeout, load_sid_allowlist,
    make_cookie, cookie_for_ip, is_policy_cookie, ip_from_cookie,
    proto_number, COOKIE_MASK_TAG_AND_IP,
)
from controller.event_log import EventLogger
settings.ensure_dirs()

# sklearn warns on every prediction (feature names); printing it per packet slows the controller
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
try:
    from ml.inference.predictor import MLPredictor
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    print(f"Warning: ML modules not available: {e}")

class SimpleSwitch13(app_manager.RyuApp):
    """Learning switch with traffic mirroring to Suricata IDS and IP blocking"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)
        self.suricata_port = {}
        self.blocked_ips = set()
        self.blocked_ips_file = str(settings.BLOCKED_IPS_FILE)
        self.alert_file = str(settings.EVE_JSON)
        self.ml_alert_file = str(settings.ML_ALERTS_FILE)  # ML predictions output for monitor.sh
        self.command_file = str(settings.COMMAND_FILE)  # Command file for unblock/management
        self.datapaths = {}
        self.alert_history = {}  # Track processed alerts: key=(sid, src_ip) -> last_seen_time
        self.alert_dedup_window = 60  # Seconds to suppress duplicate alerts for same SID+IP
        self.last_alert_position_file = str(settings.ALERT_POSITION_FILE)
        self.dropped_packet_log = {}  # Track last log time per blocked IP to reduce spam
        self.dropped_log_interval = 5  # Only log dropped packets every N seconds per IP
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'alerts_processed': 0,
            'ips_blocked': 0,
            'ml_predictions': 0,
            'ml_anomalies': 0,
            'ml_blocks': 0
        }
        
        # ML Integration
        self.ml_enabled = False
        self.ml_predictor = None
        self.ml_prediction_interval = 10  # Predict every N packets per flow to reduce overhead
        
        # 🧩 FIX 1: PER-FLOW ML STATE (moved to correct location)
        self.flow_ml_state = {}

        # Enforcement policy (Section IV): persistence, finite-lifetime scoped
        # rules, approved signatures, policy cookies, barrier verification
        self.state_lock = threading.RLock()
        self.blocks = {}                      # src IP -> BlockRecord (active decisions)
        self.offences = defaultdict(int)      # src IP -> number of blocks so far
        self.policy_mode = settings.POLICY_MODE
        self.block_scope = settings.BLOCK_SCOPE
        self.ml_block_threshold = settings.ML_CONFIDENCE
        self.ml_persistence = PersistenceTracker(settings.PERSISTENCE_R, settings.PERSISTENCE_WINDOW)
        self.sid_allowlist = load_sid_allowlist(settings.AUTO_BLOCK_SIDS_FILE)
        self.pending_barriers = {}            # xid -> (ip, dpid, sent_ts)
        self.event_log = EventLogger(settings.EVENTS_FILE, settings.CURRENT_RUN_FILE,
                                  default_policy=self.policy_mode)

        self._init_ml()
        
        # Load configurations (Suricata port is retried later if the
        # topology has not written it yet)
        if not self._load_suricata_port():
            self.logger.info("Suricata port not available yet - will load it when the topology starts")
        self._load_blocked_ips()
        
        # Start alert monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_alerts, daemon=True)
        self.monitor_thread.start()
        
        # Start command monitoring thread (for unblock commands)
        self.command_thread = threading.Thread(target=self._monitor_commands, daemon=True)
        self.command_thread.start()

        # Expire blocks whose lifetime has ended
        self.expiry_thread = threading.Thread(target=self._expiry_loop, daemon=True)
        self.expiry_thread.start()
        
        self.logger.info("=" * 60)
        self.logger.info("SDN-IDS Controller Started")
        self.logger.info("  Suricata alert monitoring: ✓ Active")
        self.logger.info("  ML-based detection: %s", "✓ Active" if self.ml_enabled else "✗ Disabled")
        self.logger.info("  Command interface: ✓ Active (%s)", self.command_file)
        self.logger.info("  Policy: mode=%s scope=%s timeout=%ss (x%.1f per repeat, max %ss)",
                         self.policy_mode, self.block_scope, settings.BLOCK_HARD_TIMEOUT,
                         settings.BLOCK_REPEAT_MULTIPLIER, settings.BLOCK_MAX_TIMEOUT)
        self.logger.info("  ML persistence: %d positives within %.0fs (RF confidence >= %.2f)",
                         settings.PERSISTENCE_R, settings.PERSISTENCE_WINDOW, self.ml_block_threshold)
        self.logger.info("  Approved SIDs: %s",
                         f"{len(self.sid_allowlist)} from {settings.AUTO_BLOCK_SIDS_FILE}"
                         if self.sid_allowlist is not None else "none (falling back to severity 1-2)")
        self.logger.info("  Live ML: %s | per-packet flow logs: %s",
                         "on" if settings.ML_LIVE else "OFF (evaluated offline)",
                         "on" if settings.VERBOSE_FLOWS else "off")
        self.logger.info("  Event log: %s", settings.EVENTS_FILE)
        self.logger.info("=" * 60)

    def _load_suricata_port(self):
        """Try once to load the Suricata mirror port from the topology's file.

        Non-blocking: the topology usually starts after the controller, so the
        file may not exist yet. Called again on switch connect and on packet-in
        until it succeeds, so start order and timing no longer matter.
        """
        if self.suricata_port:
            return True
        try:
            if os.path.exists(settings.SURICATA_PORT_FILE):
                with open(settings.SURICATA_PORT_FILE, 'r') as f:
                    content = f.read().strip()
                dpid, port = content.split(',')
                self.suricata_port[int(dpid)] = int(port)
                self.logger.info("✓ Loaded Suricata port: DPID=%s, Port=%s (from %s)",
                                 dpid, port, settings.SURICATA_PORT_FILE)
                return True
        except Exception as e:
            self.logger.debug("Suricata port file not ready yet: %s", e)
        return False

    def _load_blocked_ips(self):
        """Load blocked IPs from file"""
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            self._new_block_record(ip, reason="Restored from file",
                                                   source="restored", scope="blanket")
                self.logger.info("✓ Loaded %d blocked IPs from file", len(self.blocked_ips))
                self.stats['ips_blocked'] = len(self.blocked_ips)
        except Exception as e:
            self.logger.error("Error loading blocked IPs: %s", e)

    def _init_ml(self):
        """Initialize ML prediction pipeline"""
        if not ML_AVAILABLE:
            self.logger.warning("ML modules not available - ML-based detection disabled")
            return
        
        try:
            model_dir = str(settings.MODEL_DIR)

            self.ml_predictor = MLPredictor(
                model_dir=model_dir,
                anomaly_threshold=0.5,
                classification_threshold=0.60  # 60% confidence to block
            )
            
            if self.ml_predictor.load_models():
                self.ml_enabled = True
                self.logger.info("=" * 60)
                self.logger.info("🤖 ML PREDICTION PIPELINE INITIALIZED")
                status = self.ml_predictor.get_status()
                self.logger.info("  Anomaly Detector: %s", 
                               "✓ Ready" if status['anomaly_detector_ready'] else "✗ Not loaded")
                self.logger.info("  Attack Classifier: %s", 
                               "✓ Ready" if status['attack_classifier_ready'] else "✗ Not loaded")
                self.logger.info("  LSTM Classifier: %s", 
                               "✓ Ready" if status['lstm_classifier_ready'] else "✗ Not loaded")
                self.logger.info("  Preprocessor: %s", 
                               "✓ Ready" if status['preprocessor_ready'] else "✗ Not loaded")
                self.logger.info("=" * 60)
            else:
                self.logger.warning("ML models could not be loaded - ML detection disabled")
        except Exception as e:
            self.logger.error("Error initializing ML pipeline: %s", e)
            self.ml_enabled = False

    # 🧩 FIX 1: Helper function for flow key
    def _get_flow_key(self, src_ip, dst_ip):
        """Generate unique flow key for per-flow ML state"""
        return f"{src_ip}->{dst_ip}"

    def _extract_packet_features(self, pkt, ip_pkt, dpid, in_port):
        """
        Extract features from a packet for ML prediction.
        
        Returns tuple: (src_port, dst_port, protocol, packet_size, tcp_flags)
        """
        protocol = ip_pkt.proto
        packet_size = len(pkt.data) if hasattr(pkt, 'data') else 0
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        
        # Extract TCP info
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            # TCP flags: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
            tcp_flags = tcp_pkt.bits
        
        # Extract UDP info
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
        
        # For ICMP, ports stay at 0
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            # Use ICMP type/code as pseudo-ports for flow tracking
            src_port = icmp_pkt.type
            dst_port = icmp_pkt.code if icmp_pkt.code else 0
        
        return src_port, dst_port, protocol, packet_size, tcp_flags

    def _process_ml_prediction(self, pkt, ip_pkt, dpid, in_port):
        """
        Run ML prediction on a packet and take action if needed.
        
        Returns True if packet should be blocked, False otherwise.
        """
        if not self.ml_enabled or not self.ml_predictor:
            return False
        
        # QUICK FIX: Skip normal ICMP pings (protocol 1) - only analyze TCP/UDP
        # This prevents normal pings from being blocked during demo
        # ICMP floods will still be caught by Suricata
        if ip_pkt.proto == 1:  # ICMP
            return False
        
        try:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # 🧩 FIX 2: STOP ML IF IP IS BLOCKED
            if src_ip in self.blocked_ips:
                self.logger.debug("⛔ Skipping ML for blocked IP: %s", src_ip)
                return False
            
            # Extract packet features
            src_port, dst_port, protocol, packet_size, tcp_flags = \
                self._extract_packet_features(pkt, ip_pkt, dpid, in_port)
            
            # Get prediction from ML pipeline
            # 🧩 CRITICAL FIX: Include dpid:in_port in flow_id for per-home isolation
            result = self.ml_predictor.predict_from_packet_data(
                # flow_id=f"{dpid}:{in_port}:{src_ip}->{dst_ip}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                tcp_flags=tcp_flags,
                switch_id=dpid,
                in_port=in_port
            )
            
            # Result is None if not enough packets for prediction yet
            if result is None:
                # Log that we're accumulating packets for this flow
                flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                if hasattr(self.ml_predictor, 'flow_collector'):
                    collector = self.ml_predictor.flow_collector
                    if hasattr(collector, 'flows') and flow_key in collector.flows:
                        pkt_count = collector.flows[flow_key].packet_count
                        if pkt_count <= 3:  # Only log first few
                            self.logger.info("🔄 [ML] Collecting packets for %s (count: %d/3)",
                                           flow_key, pkt_count)
                return False
            
            self.stats['ml_predictions'] += 1
            self.logger.info("🤖 [ML] Prediction #%d: %s → %s | Type: %s (%.1f%%) | Anomaly: %.2f | Action: %s",
                           self.stats['ml_predictions'], src_ip, dst_ip, 
                           result.attack_type, result.attack_confidence * 100,
                           result.anomaly_score, result.recommendation)
            
            # Write ML prediction to file for monitor.sh
            self._write_ml_alert(result, src_ip, dst_ip)
            
            # Log anomalies
            if result.is_anomaly:
                self.stats['ml_anomalies'] += 1
                self.logger.warning("🔍 [ML] Anomaly detected: %s → %s (score: %.2f)",
                               src_ip, dst_ip, result.anomaly_score)
            
            # ML positive = anomaly detector says anomalous AND random forest says
            # attack with enough confidence (AND, not OR: fewer false blocks).
            ml_positive = (result.is_anomaly and
                           result.attack_type != 'normal' and
                           result.attack_confidence >= self.ml_block_threshold)
            if ml_positive:
                persistent = self.ml_persistence.record(src_ip)
                hits = self.ml_persistence.count(src_ip)
                self.event_log.log('ml_positive', src_ip=src_ip, dst_ip=dst_ip,
                                ip_proto=ip_pkt.proto, attack_type=result.attack_type,
                                confidence=round(float(result.attack_confidence), 4),
                                anomaly_score=round(float(result.anomaly_score), 4),
                                hits=hits, required=self.ml_persistence.r)
                self.logger.warning("🤖 [ML] Positive %d/%d for %s → %s: %s (%.1f%%, anomaly %.2f)",
                                    hits, self.ml_persistence.r, src_ip, dst_ip,
                                    result.attack_type, result.attack_confidence * 100,
                                    result.anomaly_score)

                if persistent and self._policy() in ('ml', 'hybrid'):
                    self.stats['ml_blocks'] += 1
                    reason = (f"ML: {result.attack_type} (conf {result.attack_confidence:.2f}, "
                              f"anomaly {result.anomaly_score:.2f}, {hits} positives "
                              f"in {self.ml_persistence.window:.0f}s)")
                    self._block_ip_all_switches(src_ip, reason, source='ml',
                                                dst_ip=dst_ip, ip_proto=ip_pkt.proto)
                    return True
                return False

            # Log monitoring recommendations
            if result.recommendation == 'monitor':
                lstm_info = f", LSTM: {result.lstm_attack_type}" if result.lstm_attack_type != 'unknown' else ""
                self.logger.info("👁️ [ML] Monitoring: %s → %s (anomaly: %.2f, RF: %s%s)",
                                src_ip, dst_ip, result.anomaly_score, result.attack_type, lstm_info)
            
            return False
            
        except Exception as e:
            self.logger.error("Error in ML prediction: %s", e)
            return False

    # 🧩 FIX 3: SANITIZE DATA FOR JSON
    def _sanitize_for_json(self, data):
        """Convert data to JSON-serializable format"""
        clean = {}
        for k, v in data.items():
            if isinstance(v, (bool, int, float, str, type(None))):
                clean[k] = v
            elif isinstance(v, dict):
                clean[k] = self._sanitize_for_json(v)
            elif hasattr(v, 'item'):  # numpy types
                clean[k] = v.item()
            else:
                clean[k] = str(v)
        return clean

    def _write_ml_alert(self, result, src_ip, dst_ip):
        """Write ML prediction to JSON file for external monitoring"""
        try:
            ml_alert = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "ml_prediction",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "prediction": {
                    "attack_type": result.attack_type,
                    "confidence": round(result.attack_confidence * 100, 1),
                    "anomaly_score": round(result.anomaly_score, 2),
                    "is_anomaly": result.is_anomaly,
                    "recommendation": result.recommendation,
                    "lstm_type": result.lstm_attack_type if result.lstm_attack_type != 'unknown' else None,
                    "lstm_confidence": round(result.lstm_confidence * 100, 1) if result.lstm_attack_type != 'unknown' else None
                },
                "class_probabilities": {k: round(v * 100, 1) for k, v in result.class_probabilities.items()}
            }
            
            # 🧩 FIX 3: SANITIZE BEFORE WRITING
            safe_alert = self._sanitize_for_json(ml_alert)
            
            with open(self.ml_alert_file, 'a') as f:
                json.dump(safe_alert, f)
                f.write('\n')
            self.logger.debug("📝 [ML] Alert written to %s", self.ml_alert_file)
        except Exception as e:
            self.logger.error("Could not write ML alert to file: %s", e)

    def get_ml_status(self):
        """Get ML subsystem status for monitoring"""
        if not self.ml_enabled or not self.ml_predictor:
            return {
                'enabled': False,
                'reason': 'ML not available' if not ML_AVAILABLE else 'ML not loaded'
            }
        
        status = self.ml_predictor.get_status()
        status['enabled'] = True
        status['block_threshold'] = self.ml_block_threshold
        status['controller_ml_stats'] = {
            'predictions': self.stats['ml_predictions'],
            'anomalies': self.stats['ml_anomalies'],
            'blocks': self.stats['ml_blocks']
        }
        return status

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

    def _monitor_commands(self):
        """Background thread that monitors command file for unblock/management commands"""
        self.logger.info("Command monitor ready - watching: %s", self.command_file)
        
        last_position = 0
        
        while True:
            try:
                if os.path.exists(self.command_file):
                    file_size = os.path.getsize(self.command_file)
                    
                    if file_size > last_position:
                        with open(self.command_file, 'r') as f:
                            f.seek(last_position)
                            lines = f.readlines()
                            last_position = f.tell()
                        
                        for line in lines:
                            line = line.strip()
                            if line:
                                self._process_command(line)
                    
                    elif file_size < last_position:
                        # File was truncated/rotated
                        self.logger.info("Command file was reset")
                        last_position = 0
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error("Error monitoring commands: %s", e)
                time.sleep(5)
    
    def _process_command(self, command_line):
        """Process a single command from the command file"""
        try:
            if ':' not in command_line:
                self.logger.warning("Invalid command format: %s", command_line)
                return
            
            cmd, arg = command_line.split(':', 1)
            cmd = cmd.strip().upper()
            arg = arg.strip()
            
            self.logger.info("📥 Received command: %s %s", cmd, arg)
            
            if cmd == 'UNBLOCK':
                ip_address = arg
                if self._unblock_ip_all_switches(ip_address):
                    self.logger.info("✅ Command executed successfully: UNBLOCK %s", ip_address)
                else:
                    self.logger.warning("⚠️ Command failed: UNBLOCK %s", ip_address)
            
            elif cmd == 'RESET':
                # Between experiment runs: release everything, forget history
                for ip in list(self.blocked_ips):
                    self._release_block(ip, stage='release', reason='reset')
                with self.state_lock:
                    self.offences.clear()
                self.alert_history.clear()
                self.ml_persistence = PersistenceTracker(settings.PERSISTENCE_R,
                                                         settings.PERSISTENCE_WINDOW)
                self.event_log.log('reset')
                self.logger.info("✅ Command executed successfully: RESET")

            elif cmd == 'BLOCK':
                ip_address = arg
                self._block_ip_all_switches(ip_address, "Manual block via command")
                self.logger.info("✅ Command executed successfully: BLOCK %s", ip_address)
            
            else:
                self.logger.warning("Unknown command: %s", cmd)
                
        except Exception as e:
            self.logger.error("Error processing command '%s': %s", command_line, e)

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
            
            approved = (sid in self.sid_allowlist) if self.sid_allowlist is not None \
                else severity in (1, 2)
            self.event_log.log('alert', src_ip=src_ip, dst_ip=dst_ip, sid=sid,
                            severity=severity, signature=signature,
                            proto=alert_data.get('proto'), approved=approved,
                            suricata_ts=timestamp)

            if not src_ip:
                return
            if not approved:
                self.logger.info("ℹ️ SID %s is not approved for automatic blocking - logged only", sid)
                return
            if self._policy() == 'ml':
                self.logger.info("ℹ️ Policy mode 'ml': signature alert logged, not acted on")
                return

            self.logger.warning("🚨 APPROVED SIGNATURE (SID %s, severity %s) - BLOCKING %s",
                                sid, severity, src_ip)
            self._block_ip_all_switches(src_ip, signature, source='signature',
                                        dst_ip=dst_ip,
                                        ip_proto=proto_number(alert_data.get('proto')),
                                        sid=sid)
            
        except Exception as e:
            self.logger.error("Error processing alert: %s", e)

    # ------------------------------------------------------------------
    # Enforcement: decisions, rules, verification, release
    # ------------------------------------------------------------------
    BLOCK_PRIORITY = 200

    VALID_POLICIES = ('signature', 'ml', 'hybrid')

    def _policy(self):
        """Policy for the run in progress (experiment harness can override per run)."""
        run_policy = str(self.event_log.current_run().get('policy', '')).lower()
        return run_policy if run_policy in self.VALID_POLICIES else self.policy_mode

    def _enforce(self):
        """False during capture runs: decisions are logged but no rules are installed."""
        return bool(self.event_log.current_run().get('enforce', True))

    def _new_block_record(self, ip_address, reason, source, scope=None,
                          dst_ip=None, ip_proto=None):
        """Create and register a BlockRecord (no switch messages yet)."""
        with self.state_lock:
            self.offences[ip_address] += 1
            offence = self.offences[ip_address]
            timeout = block_timeout(settings.BLOCK_HARD_TIMEOUT,
                                    settings.BLOCK_REPEAT_MULTIPLIER,
                                    settings.BLOCK_MAX_TIMEOUT, offence)
            scope = scope or self.block_scope
            if scope == 'blanket':
                dst_ip, ip_proto = None, None
            now = time.time()
            record = BlockRecord(
                ip=ip_address, cookie=make_cookie(ip_address), scope=scope,
                dst_ip=dst_ip, ip_proto=ip_proto, reason=reason, source=source,
                created=now, expires_at=(now + timeout) if timeout > 0 else None,
                offence=offence,
            )
            self.blocks[ip_address] = record
            self.blocked_ips.add(ip_address)
            self.stats['ips_blocked'] = len(self.blocked_ips)
            return record

    def _block_ip_all_switches(self, ip_address, reason="Security threat", source='manual',
                               dst_ip=None, ip_proto=None, sid=None):
        """Decide to block `ip_address` and install the rules on every switch.

        Manual blocks are blanket; signature/ML blocks follow BLOCK_SCOPE.
        Rules expire after the record's hard timeout (longer for repeat offences).
        """
        with self.state_lock:
            if ip_address in self.blocks:
                self.logger.debug("IP %s is already blocked", ip_address)
                return self.blocks[ip_address]
            scope = 'blanket' if source == 'manual' else self.block_scope
            if source in ('signature', 'ml') and not self._enforce():
                self.event_log.log('decision', src_ip=ip_address, dst_ip=dst_ip,
                                ip_proto=ip_proto, scope=scope, source=source, sid=sid,
                                reason=reason, enforced=False)
                self.logger.info("📝 Capture mode: would block %s (%s) - not enforced",
                                 ip_address, reason)
                return None
            record = self._new_block_record(ip_address, reason, source, scope=scope,
                                            dst_ip=dst_ip, ip_proto=ip_proto)
        self._save_blocked_ips()
        self.ml_persistence.reset(ip_address)

        # 🧩 FIX 4: CLEAN UP FLOW STATE WHEN BLOCKING
        keys_to_delete = [k for k in self.flow_ml_state if k.startswith(ip_address)]
        for k in keys_to_delete:
            del self.flow_ml_state[k]

        timeout = record.remaining()
        self.event_log.log('decision', src_ip=ip_address, dst_ip=record.dst_ip,
                        ip_proto=record.ip_proto, scope=record.scope, source=source,
                        sid=sid, reason=reason, cookie=hex(record.cookie),
                        offence=record.offence, timeout=timeout or 0)

        blocked_count = 0
        for dpid, datapath in list(self.datapaths.items()):
            try:
                self._install_ip_block_rules(datapath, record)
                blocked_count += 1
            except Exception as e:
                self.logger.error("Failed to block IP %s on DPID=%s: %s", ip_address, dpid, e)

        scope_desc = ("all traffic of the host" if record.scope == 'blanket' else
                      f"{ip_address} → {record.dst_ip or 'any'} proto {record.ip_proto or 'any'}")
        self.logger.warning("=" * 60)
        self.logger.warning("🔒 IP BLOCKED: %s", ip_address)
        self.logger.warning("   Reason: %s", reason)
        self.logger.warning("   Source: %s | Scope: %s", source, scope_desc)
        self.logger.warning("   Lifetime: %s (offence #%d)",
                            f"{timeout}s" if timeout else "until unblocked", record.offence)
        self.logger.warning("   Applied to: %d switches", blocked_count)
        self.logger.warning("   Total blocked IPs: %d", len(self.blocked_ips))
        self.logger.warning("=" * 60)
        return record

    def _block_matches(self, record):
        """OpenFlow matches for a block record (one per rule)."""
        if record.scope == 'blanket':
            return [dict(eth_type=0x0800, ipv4_src=record.ip),
                    dict(eth_type=0x0800, ipv4_dst=record.ip)]
        m = dict(eth_type=0x0800, ipv4_src=record.ip)
        if record.dst_ip:
            m['ipv4_dst'] = record.dst_ip
        if record.ip_proto is not None:
            m['ip_proto'] = int(record.ip_proto)
        return [m]

    def _install_ip_block_rules(self, datapath, record):
        """Install the drop rules for `record` on one switch, then ask for a barrier."""
        if isinstance(record, str):  # backwards compatibility: plain IP
            record = self.blocks.get(record) or self._new_block_record(
                record, "Manual block", "manual", scope='blanket')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        hard_timeout = record.remaining() or 0

        for m in self._block_matches(record):
            mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=record.cookie,
                priority=self.BLOCK_PRIORITY,
                match=parser.OFPMatch(**m),
                instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])],
                hard_timeout=hard_timeout,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
            )
            datapath.send_msg(mod)

        record.sent_dpids.add(datapath.id)
        record.acked_dpids.discard(datapath.id)
        self.event_log.log('flowmod_sent', src_ip=record.ip, dpid=datapath.id,
                        cookie=hex(record.cookie), hard_timeout=hard_timeout)

        # Barrier: the switch replies only after processing the FlowMods above,
        # so the reply confirms the rules are in place.
        barrier = parser.OFPBarrierRequest(datapath)
        datapath.set_xid(barrier)
        self.pending_barriers[barrier.xid] = (record.ip, datapath.id, time.time())
        datapath.send_msg(barrier)

        self.logger.info("  ✓ Installed %s block for %s on DPID=%s (priority=%d, timeout=%ss)",
                         record.scope, record.ip, datapath.id, self.BLOCK_PRIORITY,
                         hard_timeout or "none")

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        entry = self.pending_barriers.pop(ev.msg.xid, None)
        if not entry:
            return
        ip_address, dpid, sent_ts = entry
        now = time.time()
        self.event_log.log('barrier_ack', src_ip=ip_address, dpid=dpid,
                        rtt_ms=round((now - sent_ts) * 1000, 2))
        record = self.blocks.get(ip_address)
        if not record:
            return
        record.acked_dpids.add(dpid)
        if record.sent_dpids and record.acked_dpids >= record.sent_dpids:
            self.event_log.log('block_verified', src_ip=ip_address,
                            switches=len(record.acked_dpids),
                            decision_to_verified_ms=round((now - record.created) * 1000, 2))
            self.logger.info("  ✓ Block for %s confirmed by all %d switches (%.1f ms after decision)",
                             ip_address, len(record.acked_dpids), (now - record.created) * 1000)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        if not is_policy_cookie(msg.cookie):
            return
        ofproto = msg.datapath.ofproto
        reasons = {ofproto.OFPRR_IDLE_TIMEOUT: 'idle_timeout',
                   ofproto.OFPRR_HARD_TIMEOUT: 'hard_timeout',
                   ofproto.OFPRR_DELETE: 'delete'}
        self.event_log.log('flow_removed', src_ip=ip_from_cookie(msg.cookie),
                        dpid=msg.datapath.id, reason=reasons.get(msg.reason, msg.reason),
                        packets=msg.packet_count, bytes=msg.byte_count,
                        duration_s=msg.duration_sec)

    def _remove_ip_block_rules(self, datapath, ip_address):
        """Remove every policy rule for `ip_address` from one switch (cookie-masked)."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            table_id=ofproto.OFPTT_ALL,
            cookie=cookie_for_ip(ip_address),
            cookie_mask=COOKIE_MASK_TAG_AND_IP,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(mod)
        # Also remove rules from older controller versions (no cookie)
        for m in (dict(eth_type=0x0800, ipv4_src=ip_address),
                  dict(eth_type=0x0800, ipv4_dst=ip_address)):
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT,
                priority=self.BLOCK_PRIORITY, out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY, match=parser.OFPMatch(**m)))
        self.logger.info("  ✓ Removed block rules for %s on DPID=%s", ip_address, datapath.id)

    def _release_block(self, ip_address, stage='release', reason='manual'):
        """End a block: forget the decision and remove its rules everywhere."""
        with self.state_lock:
            record = self.blocks.pop(ip_address, None)
            if record is None and ip_address not in self.blocked_ips:
                return False
            self.blocked_ips.discard(ip_address)
            self.stats['ips_blocked'] = len(self.blocked_ips)
        self._save_blocked_ips()
        self.ml_persistence.reset(ip_address)

        keys_to_delete = [k for k in self.flow_ml_state if k.startswith(ip_address)]
        for k in keys_to_delete:
            del self.flow_ml_state[k]

        unblocked_count = 0
        for dpid, datapath in list(self.datapaths.items()):
            try:
                self._remove_ip_block_rules(datapath, ip_address)
                unblocked_count += 1
            except Exception as e:
                self.logger.error("Failed to unblock IP %s on DPID=%s: %s", ip_address, dpid, e)
        self.dropped_packet_log.pop(ip_address, None)
        # A new attack after release must be able to trigger a new decision
        for key in [k for k in self.alert_history if k[1] == ip_address]:
            del self.alert_history[key]

        held = round(time.time() - record.created, 2) if record else None
        self.event_log.log(stage, src_ip=ip_address, reason=reason, held_s=held,
                        switches=unblocked_count)
        self.logger.warning("=" * 60)
        self.logger.warning("🔓 IP %s: %s", "EXPIRED" if stage == 'expiry' else "UNBLOCKED", ip_address)
        if held is not None:
            self.logger.warning("   Held for: %.1fs", held)
        self.logger.warning("   Applied to: %d switches", unblocked_count)
        self.logger.warning("   Total blocked IPs: %d", len(self.blocked_ips))
        self.logger.warning("=" * 60)
        return True

    def _unblock_ip_all_switches(self, ip_address):
        """Unblock an IP address on all connected switches (manual release)."""
        if ip_address not in self.blocked_ips:
            self.logger.warning("⚠️ IP %s is not currently blocked", ip_address)
            return False
        return self._release_block(ip_address, stage='release', reason='manual')

    def _expiry_loop(self):
        """Release blocks whose lifetime has ended (switch rules expire on their own too)."""
        while True:
            try:
                now = time.time()
                with self.state_lock:
                    expired = [ip for ip, r in self.blocks.items()
                               if r.expires_at is not None and r.expires_at <= now]
                for ip in expired:
                    self._release_block(ip, stage='expiry', reason='hard_timeout')
            except Exception as e:
                self.logger.error("Error in expiry loop: %s", e)
            time.sleep(1)

    def unblock_ip(self, ip_address):
        """
        Public method to unblock an IP address.
        Can be called manually or via API/command.

        Args:
            ip_address: IP address to unblock (string)

        Returns:
            bool: True if unblocked successfully, False otherwise
        """
        return self._unblock_ip_all_switches(ip_address)

    def _save_blocked_ips(self):
        """Save blocked IPs to file (one per line; read by unblock_ip.py --list)"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                f.write(f"# Blocked IPs - Updated: {datetime.now()}\n")
                for ip in sorted(self.blocked_ips):
                    f.write(ip + '\n')
            self.logger.debug("Saved %d blocked IPs to file", len(self.blocked_ips))
        except Exception as e:
            self.logger.error("Error saving blocked IPs: %s", e)

    def _install_block_rules(self, datapath):
        """Reconcile a (re)connecting switch: install every active block with its remaining lifetime."""
        with self.state_lock:
            records = list(self.blocks.values())
        for record in records:
            self._install_ip_block_rules(datapath, record)

        if records:
            self.logger.info("  ✓ Re-installed %d active blocks on DPID=%s", len(records), datapath.id)

    def _packet_blocked(self, src_ip, dst_ip, ip_proto):
        """Return the active block that drops this packet, or None."""
        record = self.blocks.get(src_ip)
        if record and record.matches(src_ip, dst_ip, ip_proto):
            return record
        record = self.blocks.get(dst_ip)
        if record and record.scope == 'blanket':
            return record
        return None

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
        
        # Log Suricata configuration for this switch (load it now if needed)
        self._load_suricata_port()
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
        if log_flow and settings.VERBOSE_FLOWS:
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
            
            # Drop packets covered by an active block (scoped or blanket),
            # with rate-limited logging
            current_time = time.time()
            record = self._packet_blocked(src_ip, dst_ip, ip_pkt.proto)
            if record:
                self.stats['packets_blocked'] += 1
                if record.ip not in self.dropped_packet_log or \
                   current_time - self.dropped_packet_log[record.ip] > self.dropped_log_interval:
                    self.logger.warning("⛔ Dropping %s → %s (blocked: %s, count: %d)",
                                        src_ip, dst_ip, record.ip, self.stats['packets_blocked'])
                    self.dropped_packet_log[record.ip] = current_time
                return

            # Log IPv4 packets with IP addresses (only non-blocked traffic)
            self.logger.debug("[IPv4] DPID=%s %s → %s (MAC: %s → %s)",
                           dpid, src_ip, dst_ip, src, dst)
            
            # ML-based threat detection (can be switched off: SDN_ML_LIVE=false)
            if settings.ML_LIVE and self._process_ml_prediction(pkt, ip_pkt, dpid, in_port):
                # ML recommended blocking this traffic
                return
        
        # Load the Suricata port if the topology wrote it after we started
        if not self.suricata_port:
            self._load_suricata_port()

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
        # Use short idle_timeout (3s) so packets return to controller for ML analysis
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # Only log LEARN for IPv4 packets (cleaner output)
            if ip_pkt:
                mirror_info = " +mirror" if (dpid == 1 and dpid in self.suricata_port) else ""
                self.logger.debug("[LEARN] DPID=%s %s → %s port %s→%s%s",
                               dpid, ip_pkt.src, ip_pkt.dst, in_port, out_port, mirror_info)
            
            # Short idle_timeout=3 for ML to see more packets during attacks
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id, idle_timeout=3, log_flow=ip_pkt is not None)
                return
            else:
                self.add_flow(datapath, 10, match, actions, idle_timeout=3, log_flow=ip_pkt is not None)
        
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