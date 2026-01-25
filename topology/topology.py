#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import subprocess

# Central veth map
VETH_MAP = {
    "h1": ("172.16.3.1/30", "172.16.3.2/30"),
    "h3": ("172.16.4.1/30", "172.16.4.2/30"),
    "h5": ("172.16.5.1/30", "172.16.5.2/30"),
    "h7": ("172.16.7.1/30", "172.16.7.2/30"),  # SOC
}


class CustomTopology(Topo):
    """
    Custom SDN Topology with VLANs and Suricata IDS
    """

    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')
        s5 = self.addSwitch('s5', protocols='OpenFlow13')

        suricata = self.addHost('suricata', ip='10.0.0.100/24')

        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h3 = self.addHost('h3', ip='10.0.1.3/24')
        h5 = self.addHost('h5', ip='10.0.1.5/24')
        h7 = self.addHost('h7', ip='10.0.1.7/24')

        h2 = self.addHost('h2', ip='10.0.2.2/24')
        h4 = self.addHost('h4', ip='10.0.2.4/24')
        h6 = self.addHost('h6', ip='10.0.2.6/24')
        h8 = self.addHost('h8', ip='10.0.2.8/24')

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
    Creates a veth pair between Node-RED (host OS)
    and a Mininet host namespace.
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

    subprocess.run(
        ["ip", "link", "set", veth_mn, "netns", str(pid)],
        check=True
    )

    host.cmd(f"ip addr add {mn_ip} dev {veth_mn}")
    host.cmd(f"ip link set {veth_mn} up")

    info(f"*** veth configured for {host_name}\n")


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

    # loop-based setup
    for host, (host_ip, mn_ip) in VETH_MAP.items():
        add_veth_to_host(net, host, host_ip, mn_ip)

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()
