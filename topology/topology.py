#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class CustomTopology(Topo):
    """
    Custom SDN Topology with VLANs and Suricata IDS
    - 1 Main switch (S1) connected to SDN controller and Suricata
    - 4 Access switches (S2, S3, S4, S5)
    - 8 Hosts (h1-h8)
    - 1 Suricata IDS host
    - VLAN1 (10.0.1.x): h1, h3, h5, h7
    - VLAN2 (10.0.2.x): h2, h4, h6, h8
    """
    
    def build(self):
        # Add main switch S1
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        # Add access switches S2, S3, S4, S5
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')
        s5 = self.addSwitch('s5', protocols='OpenFlow13')
        
        # Add Suricata IDS host connected to S1
        suricata = self.addHost('suricata', ip='10.0.0.100/24', mac='00:00:00:00:00:99')
        
        # Add hosts with VLAN-specific IP addressing
        # VLAN1 (10.0.1.x) - h1, h3, h5, h7
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:00:01')
        h3 = self.addHost('h3', ip='10.0.1.3/24', mac='00:00:00:00:00:03')
        h5 = self.addHost('h5', ip='10.0.1.5/24', mac='00:00:00:00:00:05')
        h7 = self.addHost('h7', ip='10.0.1.7/24', mac='00:00:00:00:00:07')
        
        # VLAN2 (10.0.2.x) - h2, h4, h6, h8
        h2 = self.addHost('h2', ip='10.0.2.2/24', mac='00:00:00:00:00:02')
        h4 = self.addHost('h4', ip='10.0.2.4/24', mac='00:00:00:00:00:04')
        h6 = self.addHost('h6', ip='10.0.2.6/24', mac='00:00:00:00:00:06')
        h8 = self.addHost('h8', ip='10.0.2.8/24', mac='00:00:00:00:00:08')
        
        # Link S1 to Suricata IDS (MUST be first link to S1)
        self.addLink(s1, suricata)
        
        # Link S1 to access switches
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s1, s5)
        
        # Link hosts to access switches
        # S2 connects to h1 (VLAN1), h2 (VLAN2)
        self.addLink(s2, h1)
        self.addLink(s2, h2)
        
        # S3 connects to h3 (VLAN1), h4 (VLAN2)
        self.addLink(s3, h3)
        self.addLink(s3, h4)
        
        # S4 connects to h5 (VLAN1), h6 (VLAN2)
        self.addLink(s4, h5)
        self.addLink(s4, h6)
        
        # S5 connects to h7 (VLAN1), h8 (VLAN2)
        self.addLink(s5, h7)
        self.addLink(s5, h8)

def startNetwork():
    """Start the network with remote controller"""
    topo = CustomTopology()
    
    # Create network with remote controller
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info('*** Starting network\n')
    net.start()
    
    info('*** Network Configuration:\n')
    info('*** VLAN1 (10.0.1.x): h1, h3, h5, h7\n')
    info('*** VLAN2 (10.0.2.x): h2, h4, h6, h8\n')
    info('\n')
    
    # Find Suricata and S1
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
    
    if s1 and suricata:
        # Find which port Suricata is connected to on S1
        suricata_port = None
        for intf in s1.intfList():
            if hasattr(intf, 'link') and intf.link:
                link = intf.link
                if link.intf1.node == suricata or link.intf2.node == suricata:
                    # Get the port number on S1 side
                    if link.intf1.node == s1:
                        suricata_port = s1.ports[link.intf1]
                    else:
                        suricata_port = s1.ports[link.intf2]
                    break
        
        if suricata_port:
            info(f'*** Suricata connected to S1 on port: {suricata_port}\n')
            
            # Store suricata port in a file for controller to read
            try:
                with open('/tmp/suricata_port.txt', 'w') as f:
                    f.write(f'{s1.dpid},{suricata_port}')
                info('*** Suricata port info saved to /tmp/suricata_port.txt\n')
            except Exception as e:
                info(f'*** Error saving Suricata port info: {e}\n')
        else:
            info('*** Warning: Could not determine Suricata port\n')
    else:
        info('*** Warning: Could not find S1 or Suricata\n')
    
    info('\n*** Switches:\n')
    for switch in net.switches:
        info(f'{switch.name} ')
    info('\n\n')
    
    info('*** Hosts and their IPs:\n')
    info('VLAN1:\n')
    for host_name in ['h1', 'h3', 'h5', 'h7']:
        host = net[host_name]
        info(f'  {host.name}: {host.IP()}\n')
    
    info('VLAN2:\n')
    for host_name in ['h2', 'h4', 'h6', 'h8']:
        host = net[host_name]
        info(f'  {host.name}: {host.IP()}\n')
    
    if suricata:
        info(f'Suricata IDS: {suricata.IP()}\n')
    info('\n')
    
    info('*** Running CLI\n')
    info('*** Type "help" for available commands\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()
