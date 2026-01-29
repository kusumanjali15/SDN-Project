#!/usr/bin/python
"""
Merged SDN-IoT Topology
Combines:
- Kusuma: Suricata IDS integration with OVS mirroring
- Saikiran: Veth pairs for Node-RED IoT traffic injection
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import subprocess

# Veth configuration for Node-RED connectivity
VETH_MAP = {
    "h1": ("172.16.3.1/30", "172.16.3.2/30"),  # Temperature Sensor
    "h3": ("172.16.4.1/30", "172.16.4.2/30"),  # Smart Light
    "h5": ("172.16.5.1/30", "172.16.5.2/30"),  # Security Camera
    "h7": ("172.16.7.1/30", "172.16.7.2/30"),  # Smart Thermostat
}

class IoTSDNTopology(Topo):
    """
    Merged SDN Topology with IoT Integration
    - 1 Main switch (S1) with Suricata IDS
    - 4 Access switches (S2-S5)
    - 8 Hosts (h1-h8) as IoT devices
    - 1 Suricata IDS host
    - Veth pairs for Node-RED connectivity to h1, h3, h5, h7
    
    Network Design:
    - VLAN1 (10.0.1.x): h1, h3, h5, h7 (IoT Sensors with Node-RED)
    - VLAN2 (10.0.2.x): h2, h4, h6, h8 (IoT Actuators)
    - Veth (172.16.x.x): Node-RED ↔ Mininet bridge
    """
    
    def build(self):
        # Main switch S1 - all traffic mirrors to Suricata
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        # Access switches
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')
        s5 = self.addSwitch('s5', protocols='OpenFlow13')
        
        # Suricata IDS host (MUST be first connection to S1)
        suricata = self.addHost('suricata', ip='10.0.0.100/24', mac='00:00:00:00:00:99')
        
        # IoT Devices - VLAN1 (with Node-RED veth connections)
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:00:01')  # Temperature
        h3 = self.addHost('h3', ip='10.0.1.3/24', mac='00:00:00:00:00:03')  # Light
        h5 = self.addHost('h5', ip='10.0.1.5/24', mac='00:00:00:00:00:05')  # Camera
        h7 = self.addHost('h7', ip='10.0.1.7/24', mac='00:00:00:00:00:07')  # Thermostat
        
        # IoT Devices - VLAN2 (internal only)
        h2 = self.addHost('h2', ip='10.0.2.2/24', mac='00:00:00:00:00:02')  # Motion
        h4 = self.addHost('h4', ip='10.0.2.4/24', mac='00:00:00:00:00:04')  # Lock
        h6 = self.addHost('h6', ip='10.0.2.6/24', mac='00:00:00:00:00:06')  # Alarm
        h8 = self.addHost('h8', ip='10.0.2.8/24', mac='00:00:00:00:00:08')  # Hub
        
        # CRITICAL: Suricata link must be FIRST
        self.addLink(s1, suricata)
        
        # Link switches
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s1, s5)
        
        # Link hosts to switches
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
    Creates veth pair between Node-RED (host OS) and Mininet host.
    This allows Node-RED to send traffic directly into Mininet.
    
    Args:
        host_name: Name of Mininet host (e.g., 'h1')
        host_ip: IP on host OS side (e.g., '172.16.3.1/30')
        mn_ip: IP on Mininet side (e.g., '172.16.3.2/30')
    """
    host = net.get(host_name)
    pid = host.pid

    veth_host = f"veth-host-{host_name}"
    veth_mn = f"veth-{host_name}"

    # Create veth pair
    try:
        subprocess.run(
            ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_mn],
            check=True
        )
        
        # Configure host OS side
        subprocess.run(["ip", "addr", "add", host_ip, "dev", veth_host], check=True)
        subprocess.run(["ip", "link", "set", veth_host, "up"], check=True)
        
        # Move Mininet side into host namespace
        subprocess.run(
            ["ip", "link", "set", veth_mn, "netns", str(pid)],
            check=True
        )
        
        # Configure Mininet side
        host.cmd(f"ip addr add {mn_ip} dev {veth_mn}")
        host.cmd(f"ip link set {veth_mn} up")
        
        info(f"*** Veth configured for {host_name}: {veth_host} ↔ {veth_mn}\n")
        info(f"    Host OS: {host_ip}, Mininet: {mn_ip}\n")
        
    except subprocess.CalledProcessError as e:
        info(f"*** Error creating veth for {host_name}: {e}\n")


def startNetwork():
    """Start the merged IoT-SDN network"""
    topo = IoTSDNTopology()
    
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info('╔════════════════════════════════════════════════════════════╗\n')
    info('║          IoT-SDN Network with Suricata IDS                ║\n')
    info('╚════════════════════════════════════════════════════════════╝\n')
    info('\n')
    
    info('*** Starting network\n')
    net.start()
    
    # Find S1 and Suricata for port mapping
    s1 = None
    suricata = None
    
    for switch in net.switches:
        if switch.name == 's1':
            s1 = switch
            break
    
    for host in net.hosts:
        if host.name == 'suricata':
            suricata = host
            break
    
    # Configure Suricata port mapping
    if s1 and suricata:
        suricata_port = None
        for intf in s1.intfList():
            if hasattr(intf, 'link') and intf.link:
                link = intf.link
                if link.intf1.node == suricata or link.intf2.node == suricata:
                    if link.intf1.node == s1:
                        suricata_port = s1.ports[link.intf1]
                    else:
                        suricata_port = s1.ports[link.intf2]
                    break
        
        if suricata_port:
            info(f'*** Suricata connected to S1 on port: {suricata_port}\n')
            try:
                with open('/tmp/suricata_port.txt', 'w') as f:
                    f.write(f'{s1.dpid},{suricata_port}')
                info('*** Suricata port saved to /tmp/suricata_port.txt\n')
            except Exception as e:
                info(f'*** Error saving Suricata port: {e}\n')
        else:
            info('*** WARNING: Could not determine Suricata port\n')
    else:
        info('*** WARNING: Could not find S1 or Suricata\n')
    
    # Create veth pairs for Node-RED connectivity
    info('\n*** Creating veth pairs for Node-RED...\n')
    for host_name, (host_ip, mn_ip) in VETH_MAP.items():
        add_veth_to_host(net, host_name, host_ip, mn_ip)
    
    # Display network information
    info('\n')
    info('╔════════════════════════════════════════════════════════════╗\n')
    info('║                 Network Configuration                     ║\n')
    info('╚════════════════════════════════════════════════════════════╝\n')
    info('\n')
    
    info('*** Switches:\n')
    for switch in net.switches:
        info(f'  {switch.name}\n')
    
    info('\n*** IoT Devices (VLAN1 - with Node-RED):\n')
    device_names = {
        'h1': 'Temperature Sensor',
        'h3': 'Smart Light',
        'h5': 'Security Camera',
        'h7': 'Smart Thermostat'
    }
    for host_name in ['h1', 'h3', 'h5', 'h7']:
        host = net[host_name]
        veth_info = VETH_MAP[host_name]
        info(f'  {host.name} ({device_names[host_name]}): {host.IP()}\n')
        info(f'    Node-RED veth: {veth_info[0]} ↔ {veth_info[1]}\n')
    
    info('\n*** IoT Devices (VLAN2 - internal):\n')
    device_names_vlan2 = {
        'h2': 'Motion Detector',
        'h4': 'Smart Lock',
        'h6': 'Alarm System',
        'h8': 'Smart Hub'
    }
    for host_name in ['h2', 'h4', 'h6', 'h8']:
        host = net[host_name]
        info(f'  {host.name} ({device_names_vlan2[host_name]}): {host.IP()}\n')
    
    if suricata:
        info(f'\n*** Suricata IDS: {suricata.IP()}\n')
    
    info('\n')
    info('╔════════════════════════════════════════════════════════════╗\n')
    info('║                 Node-RED Configuration                    ║\n')
    info('╚════════════════════════════════════════════════════════════╝\n')
    info('\n')
    info('Configure Node-RED MQTT/HTTP nodes to use these endpoints:\n')
    info('  h1 (Temperature): 172.16.3.1\n')
    info('  h3 (Light):       172.16.4.1\n')
    info('  h5 (Camera):      172.16.5.1\n')
    info('  h7 (Thermostat):  172.16.7.1\n')
    info('\n')
    
    info('╔════════════════════════════════════════════════════════════╗\n')
    info('║                   Testing Commands                        ║\n')
    info('╚════════════════════════════════════════════════════════════╝\n')
    info('\n')
    info('1. Test veth connectivity from host:\n')
    info('   ping -c 3 172.16.3.2  # Ping h1 from host OS\n')
    info('\n')
    info('2. Test internal connectivity:\n')
    info('   mininet> h1 ping -c 3 h2\n')
    info('\n')
    info('3. Generate attack (ICMP flood):\n')
    info('   mininet> h1 ping -c 25 -i 0.2 h3\n')
    info('\n')
    info('4. Simulate Node-RED traffic:\n')
    info('   # From host OS:\n')
    info('   curl http://172.16.3.2:8080/sensor/temperature\n')
    info('\n')
    
    info('*** Running CLI\n')
    info('*** Type "help" for available commands\n')
    CLI(net)
    
    info('*** Stopping network\n')
    
    # Cleanup veth pairs
    info('*** Cleaning up veth pairs\n')
    for host_name in VETH_MAP.keys():
        veth_host = f"veth-host-{host_name}"
        try:
            subprocess.run(["ip", "link", "delete", veth_host], 
                         stderr=subprocess.DEVNULL)
        except:
            pass
    
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()
