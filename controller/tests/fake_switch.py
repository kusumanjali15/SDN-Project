"""Minimal OpenFlow 1.3 switch: handshake, answers echo/port-desc/barrier, sends an ARP packet-in."""
import socket, struct, sys, time, threading
# Runs with the Ryu venv: python controller/tests/fake_switch.py <dpid> <seconds>
from ryu.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as p, ofproto_parser
from ryu.lib.packet import packet, ethernet, arp
dpid = int(sys.argv[1]); log = open(f"/tmp/fake_switch_{dpid}.log", "w")
class DP:  # enough for serialize()
    ofproto = ofp; ofproto_parser = p
dp = DP()
s = socket.create_connection(("127.0.0.1", 6653))
def raw(typ, body=b"", xid=0):
    s.sendall(struct.pack("!BBHI", 4, typ, 8 + len(body), xid) + body)
def send(msg, xid=None):
    msg.datapath = dp
    if xid is not None: msg.set_xid(xid)
    elif msg.xid is None: msg.set_xid(0)
    msg.serialize(); s.sendall(msg.buf)
send(p.OFPHello(dp))
buf = b""; got = []
def pkt_in():
    e = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:01", ethertype=0x0806)
    a = arp.arp(src_mac="00:00:00:00:00:01", src_ip="10.0.1.1", dst_mac="00:00:00:00:00:00", dst_ip="10.0.1.3")
    pk = packet.Packet(); pk.add_protocol(e); pk.add_protocol(a); pk.serialize()
    match = struct.pack("!HH", 1, 12) + struct.pack("!HBBI", 0x8000, 0, 4, 2) + b"\x00" * 4
    body = struct.pack("!IHBBQ", 0xffffffff, len(pk.data), 0, 0, 0) + match + b"\x00\x00" + pk.data
    raw(10, body)
deadline = time.time() + float(sys.argv[2])
s.settimeout(0.5)
sent_pi = False
while time.time() < deadline:
    try:
        d = s.recv(65535)
        if not d: break
        buf += d
    except socket.timeout:
        d = b""
    while len(buf) >= 8:
        ver, typ, length, xid = struct.unpack("!BBHI", buf[:8])
        if len(buf) < length: break
        raw_msg, buf = buf[:length], buf[length:]
        names = {0:"HELLO",2:"ECHO_REQUEST",5:"FEATURES_REQUEST",9:"SET_CONFIG",13:"PACKET_OUT",
                 14:"FLOW_MOD",18:"MULTIPART_REQUEST",20:"BARRIER_REQUEST"}
        name = names.get(typ, f"type{typ}")
        if typ == 14:  # decode FlowMod fields we care about
            cookie, cmask, table, cmd, idle, hard, prio = struct.unpack("!QQBBHHH", raw_msg[8:32])
            name += f" cmd={cmd} prio={prio} hard={hard} cookie={cookie:#x}"
        got.append(name); log.write(name + "\n"); log.flush()
        if typ == 5:
            raw(6, struct.pack("!QIBBxxII", dpid, 0, 254, 0, 0, 0), xid)
        elif typ == 2:
            raw(3, raw_msg[8:], xid)
        elif typ == 18:
            raw(19, struct.pack("!HHxxxx", 13, 0), xid)
        elif typ == 20:
            raw(21, b"", xid)
    if not sent_pi and "MULTIPART_REQUEST" in got:
        time.sleep(0.5); pkt_in(); sent_pi = True
log.close()
