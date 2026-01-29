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


# Central veth map (Node-RED ↔ Mininet)
VETH_MAP = {
    "h1": ("172.16.3.1/30", "172.16.3.2/30"),
    "h3": ("172.16.4.1/30", "172.16.4.2/30"),
    "h5": ("172.16.5.1/30", "172.16.5.2/30"),
    "h7": ("172.16.7.1/30", "172.16.7.2/30"),  # SOC / special endpoint
}


class CustomTopology(Topo):
    """
    SDN Topology:
    - Core switch s1
    - Access switches s2–s5
    - Hosts h1–h8
    - Suricata IDS attached to s1
    """

    def build(self):
        # Switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')
        s5 = self.addSwitch('s5', protocols='OpenFlow13')

        # Suricata IDS host (must be first link on s1)
        suricata = self.addHost('suricata', ip='10.0.0.100/24')

        # VLAN 1 hosts
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h3 = self.addHost('h3', ip='10.0.1.3/24')
        h5 = self.addHost('h5', ip='10.0.1.5/24')
        h7 = self.addHost('h7', ip='10.0.1.7/24')

        # VLAN 2 hosts
        h2 = self.addHost('h2', ip='10.0.2.2/24')
        h4 = self.addHost('h4', ip='10.0.2.4/24')
        h6 = self.addHost('h6', ip='10.0.2.6/24')
        h8 = self.addHost('h8', ip='10.0.2.8/24')

        # Links
        self.addLink(s1, suricata)

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s1, s5)

        self.addLink(s2, h1)
        self.addLink(s2, h2)

        self.addLink(s3, h3)
        self.addLink(s3, h4)

        self.addLink(s4, h5)
        self.addLink(s4, h6)

        self.addLink(s5, h7)
        self.addLink(s5, h8)


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
            with open('/tmp/suricata_port.txt', 'w') as f:
                f.write(f"{s1.dpid},{port}")
            info(f"*** Suricata port saved: {s1.dpid},{port}\n")
            return

    info("*** WARNING: Could not determine Suricata port\n")


def startNetwork():
    topo = CustomTopology()

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
