#!/usr/bin/python
"""
Unified SDN-IoT Topology

Priority:
1. Preserve proven working behavior (veth + Node-RED + Mininet)
2. Keep required features from main (Suricata port export)
3. Remove semantic assumptions and fragile logic
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import subprocess
import os
import sys

# Make the repo root importable when run as `sudo python3 topology/topology.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings


# Central veth map (Node-RED ↔ Mininet)
VETH_MAP = {
    "h1": ("172.16.3.1/30", "172.16.3.2/30"),
    "h3": ("172.16.4.1/30", "172.16.4.2/30"),
    "h5": ("172.16.5.1/30", "172.16.5.2/30"),
    "h7": ("172.16.7.1/30", "172.16.7.2/30"),  # SOC / special endpoint
}


def host_layout(hosts_per_switch=2):
    """(name, ip, vlan, switch) for every host.

    Default (2 per access switch) is the original 8-host topology:
    h1/h2 on s2, h3/h4 on s3, h5/h6 on s4, h7/h8 on s5. Larger sizes keep the
    same pattern: odd hosts are VLAN 1 (10.0.1.n), even hosts VLAN 2
    (10.0.2.n), and pairs are spread round-robin over s2..s5.
    Set SDN_HOSTS_PER_SWITCH in the environment or .env for the scalability
    sweep (e.g. 8 -> 32 hosts, 16 -> 64 hosts).
    """
    total = 4 * hosts_per_switch
    layout = []
    for n in range(1, total + 1):
        vlan = 1 if n % 2 else 2
        switch = f"s{2 + ((n - 1) // 2) % 4}"
        layout.append((f"h{n}", f"10.0.{vlan}.{n}", vlan, switch))
    return layout


def hosts_per_switch():
    try:
        return max(2, int(os.environ.get("SDN_HOSTS_PER_SWITCH", "2") or 2))
    except ValueError:
        return 2


class CustomTopology(Topo):
    """
    SDN Topology:
    - Core switch s1
    - Access switches s2-s5
    - Hosts h1-hN (N = 8 by default, see host_layout)
    - Suricata IDS attached to s1
    """

    def build(self, per_switch=2):
        # Switches
        switches = {f"s{i}": self.addSwitch(f"s{i}", protocols='OpenFlow13') for i in range(1, 6)}

        # Suricata IDS host (must be first link on s1)
        suricata = self.addHost('suricata', ip='10.0.0.100/24')
        self.addLink(switches["s1"], suricata)

        # Core to access links
        for i in range(2, 6):
            self.addLink(switches["s1"], switches[f"s{i}"])

        # Hosts: VLAN 1 = 10.0.1.x (odd), VLAN 2 = 10.0.2.x (even)
        for name, ip, _vlan, sw in host_layout(per_switch):
            h = self.addHost(name, ip=f"{ip}/24")
            self.addLink(switches[sw], h)


def add_veth_to_host(net, host_name, host_ip, mn_ip):
    """
    Create veth pair between host OS (Node-RED) and Mininet host.
    """
    host = net.get(host_name)
    pid = host.pid

    veth_host = f"veth-host-{host_name}"
    veth_mn = f"veth-{host_name}"

    subprocess.run(
        ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_mn],
        check=True
    )

    subprocess.run(["ip", "addr", "add", host_ip, "dev", veth_host], check=True)
    subprocess.run(["ip", "link", "set", veth_host, "up"], check=True)

    subprocess.run(["ip", "link", "set", veth_mn, "netns", str(pid)], check=True)

    host.cmd(f"ip addr add {mn_ip} dev {veth_mn}")
    host.cmd(f"ip link set {veth_mn} up")

    info(f"*** veth configured for {host_name}\n")


def export_suricata_port(net):
    """
    Export Suricata port info for setup_mirror.sh
    """
    s1 = net.get('s1')
    suricata = net.get('suricata')

    for intf in s1.intfList():
        if intf.link and (
            intf.link.intf1.node == suricata or
            intf.link.intf2.node == suricata
        ):
            port = s1.ports[intf]
            settings.ensure_dirs()
            with open(settings.SURICATA_PORT_FILE, 'w') as f:
                f.write(f"{s1.dpid},{port}")
            info(f"*** Suricata port saved: {s1.dpid},{port}\n")
            return

    info("*** WARNING: Could not determine Suricata port\n")


def startNetwork():
    per_switch = hosts_per_switch()
    info(f'*** {4 * per_switch} hosts ({per_switch} per access switch)\n')
    topo = CustomTopology(per_switch=per_switch)

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info('*** Starting network\n')
    net.start()

    export_suricata_port(net)

    for host, (host_ip, mn_ip) in VETH_MAP.items():
        add_veth_to_host(net, host, host_ip, mn_ip)

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()
