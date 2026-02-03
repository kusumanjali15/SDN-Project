#!/usr/bin/env python3
"""
Dataset Generator for SDN-IDS ML Training

Generates synthetic network traffic data that matches your SDN environment:
- Normal traffic between hosts in VLANs
- DDoS attacks (ICMP flood, SYN flood, UDP flood)
- Port scanning attacks
- Brute force attacks

This creates labeled data for training anomaly detection and LSTM models.
"""

import numpy as np
import pandas as pd
import os
from datetime import datetime, timedelta
import random

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

# Your SDN network configuration
VLAN1_HOSTS = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4']  # h1, h3, h5, h7
VLAN2_HOSTS = ['10.0.2.1', '10.0.2.2', '10.0.2.3', '10.0.2.4']  # h2, h4, h6, h8
ALL_HOSTS = VLAN1_HOSTS + VLAN2_HOSTS
SURICATA_IP = '10.0.0.100'

# Common ports
COMMON_PORTS = [80, 443, 22, 8080, 3306, 5432, 6379, 27017]


def generate_normal_flow():
    """Generate a normal traffic flow"""
    src_ip = random.choice(ALL_HOSTS)
    dst_ip = random.choice([h for h in ALL_HOSTS if h != src_ip])
    
    # Normal traffic characteristics
    protocol = random.choice([6, 6, 6, 17, 1])  # Mostly TCP, some UDP, few ICMP
    
    if protocol == 1:  # ICMP
        src_port = 0
        dst_port = 0
        packet_count = random.randint(1, 5)
        byte_count = packet_count * random.randint(64, 128)
        duration = random.uniform(0.1, 2.0)
    elif protocol == 6:  # TCP
        src_port = random.randint(32768, 65535)
        dst_port = random.choice(COMMON_PORTS)
        packet_count = random.randint(5, 100)
        byte_count = packet_count * random.randint(100, 1500)
        duration = random.uniform(0.5, 30.0)
    else:  # UDP
        src_port = random.randint(32768, 65535)
        dst_port = random.choice([53, 123, 161, 514])
        packet_count = random.randint(1, 20)
        byte_count = packet_count * random.randint(50, 512)
        duration = random.uniform(0.1, 5.0)
    
    return create_flow_record(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, byte_count,
        syn_count=random.randint(1, 3) if protocol == 6 else 0,
        ack_count=random.randint(1, packet_count) if protocol == 6 else 0,
        label='normal'
    )


def generate_ddos_flow():
    """Generate DDoS attack flow"""
    attacker_ip = random.choice(ALL_HOSTS[:4])  # Attacker from VLAN1
    victim_ip = random.choice(ALL_HOSTS[4:])     # Victim in VLAN2
    
    attack_type = random.choice(['icmp_flood', 'syn_flood', 'udp_flood'])
    
    if attack_type == 'icmp_flood':
        protocol = 1
        src_port = 0
        dst_port = 0
        packet_count = random.randint(100, 500)
        byte_count = packet_count * random.randint(64, 128)
        duration = random.uniform(5.0, 30.0)
        syn_count = 0
        ack_count = 0
    elif attack_type == 'syn_flood':
        protocol = 6
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 8080])
        packet_count = random.randint(200, 1000)
        byte_count = packet_count * 60  # SYN packets are small
        duration = random.uniform(5.0, 60.0)
        syn_count = packet_count  # All SYN, no ACK
        ack_count = 0
    else:  # udp_flood
        protocol = 17
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535)
        packet_count = random.randint(500, 2000)
        byte_count = packet_count * random.randint(512, 1400)
        duration = random.uniform(5.0, 60.0)
        syn_count = 0
        ack_count = 0
    
    return create_flow_record(
        attacker_ip, victim_ip, src_port, dst_port, protocol,
        duration, packet_count, byte_count,
        syn_count=syn_count,
        ack_count=ack_count,
        label='ddos'
    )


def generate_portscan_flow():
    """Generate port scanning flow"""
    scanner_ip = random.choice(ALL_HOSTS)
    target_ip = random.choice([h for h in ALL_HOSTS if h != scanner_ip])
    
    protocol = 6  # TCP
    src_port = random.randint(32768, 65535)
    dst_port = random.randint(1, 1024)  # Scanning common ports
    
    # Port scans have few packets per port, many different ports
    packet_count = random.randint(1, 3)
    byte_count = packet_count * 60
    duration = random.uniform(0.01, 0.5)  # Very short connections
    
    return create_flow_record(
        scanner_ip, target_ip, src_port, dst_port, protocol,
        duration, packet_count, byte_count,
        syn_count=packet_count,  # All SYN
        ack_count=0,
        fin_count=0,
        rst_count=random.randint(0, packet_count),  # RST responses
        label='portscan'
    )


def generate_bruteforce_flow():
    """Generate brute force attack flow"""
    attacker_ip = random.choice(ALL_HOSTS)
    victim_ip = random.choice([h for h in ALL_HOSTS if h != attacker_ip])
    
    protocol = 6
    src_port = random.randint(32768, 65535)
    dst_port = random.choice([22, 21, 23, 3389])  # SSH, FTP, Telnet, RDP
    
    # Brute force has many connection attempts
    packet_count = random.randint(10, 50)
    byte_count = packet_count * random.randint(100, 500)
    duration = random.uniform(1.0, 10.0)
    
    return create_flow_record(
        attacker_ip, victim_ip, src_port, dst_port, protocol,
        duration, packet_count, byte_count,
        syn_count=random.randint(5, 20),  # Many connection attempts
        ack_count=random.randint(0, 10),
        fin_count=random.randint(0, 5),
        rst_count=random.randint(5, 15),  # Many failed connections
        label='bruteforce'
    )


def create_flow_record(src_ip, dst_ip, src_port, dst_port, protocol,
                       duration, packet_count, byte_count,
                       syn_count=0, ack_count=0, fin_count=0, rst_count=0, psh_count=0,
                       label='normal'):
    """Create a flow record with all features"""
    
    # Calculate derived features
    packets_per_second = packet_count / max(duration, 0.001)
    bytes_per_second = byte_count / max(duration, 0.001)
    avg_packet_size = byte_count / max(packet_count, 1)
    
    # Inter-arrival time statistics
    if packet_count > 1:
        iat_mean = duration / (packet_count - 1)
        iat_std = iat_mean * random.uniform(0.1, 0.5)
        iat_min = iat_mean * random.uniform(0.1, 0.5)
        iat_max = iat_mean * random.uniform(1.5, 3.0)
    else:
        iat_mean = iat_std = iat_min = iat_max = 0
    
    # Packet size variation
    min_packet_size = int(avg_packet_size * random.uniform(0.3, 0.8))
    max_packet_size = int(avg_packet_size * random.uniform(1.2, 2.0))
    
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'duration': round(duration, 4),
        'packet_count': packet_count,
        'byte_count': byte_count,
        'packets_per_second': round(packets_per_second, 2),
        'bytes_per_second': round(bytes_per_second, 2),
        'avg_packet_size': round(avg_packet_size, 2),
        'min_packet_size': min_packet_size,
        'max_packet_size': max_packet_size,
        'iat_mean': round(iat_mean, 6),
        'iat_std': round(iat_std, 6),
        'iat_min': round(iat_min, 6),
        'iat_max': round(iat_max, 6),
        'syn_count': syn_count,
        'ack_count': ack_count,
        'fin_count': fin_count,
        'rst_count': rst_count,
        'psh_count': psh_count,
        'label': label
    }


def generate_packet_sequence(flow_record, sequence_length=100):
    """Generate a sequence of packets from a flow record for LSTM training"""
    packets = []
    
    protocol = flow_record['protocol']
    src_ip = flow_record['src_ip']
    dst_ip = flow_record['dst_ip']
    src_port = flow_record['src_port']
    dst_port = flow_record['dst_port']
    label = flow_record['label']
    
    duration = flow_record['duration']
    packet_count = min(flow_record['packet_count'], sequence_length)
    
    base_time = 0
    time_step = duration / max(packet_count, 1)
    
    for i in range(sequence_length):
        if i < packet_count:
            # Generate actual packet
            packet_size = random.randint(
                flow_record['min_packet_size'],
                flow_record['max_packet_size']
            )
            
            # TCP flags based on attack type
            if protocol == 6:
                if label == 'ddos' and 'syn_flood' in str(flow_record):
                    tcp_flags = 2  # SYN only
                elif label == 'portscan':
                    tcp_flags = random.choice([2, 4])  # SYN or RST
                else:
                    tcp_flags = random.choice([2, 16, 18, 24])  # Various flags
            else:
                tcp_flags = 0
            
            timestamp = base_time + i * time_step + random.uniform(0, time_step * 0.1)
        else:
            # Padding with zeros for sequences shorter than sequence_length
            packet_size = 0
            tcp_flags = 0
            timestamp = 0
        
        packets.append({
            'timestamp': round(timestamp, 6),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'tcp_flags': tcp_flags,
            'label': label
        })
    
    return packets


def generate_dataset(n_normal=10000, n_ddos=3000, n_portscan=2000, n_bruteforce=1500):
    """Generate complete training dataset"""
    
    print("Generating SDN-IDS training dataset...")
    print(f"  Normal flows: {n_normal}")
    print(f"  DDoS flows: {n_ddos}")
    print(f"  Port scan flows: {n_portscan}")
    print(f"  Brute force flows: {n_bruteforce}")
    
    flows = []
    
    # Generate normal traffic
    print("Generating normal traffic...")
    for _ in range(n_normal):
        flows.append(generate_normal_flow())
    
    # Generate DDoS attacks
    print("Generating DDoS attacks...")
    for _ in range(n_ddos):
        flows.append(generate_ddos_flow())
    
    # Generate port scans
    print("Generating port scans...")
    for _ in range(n_portscan):
        flows.append(generate_portscan_flow())
    
    # Generate brute force attacks
    print("Generating brute force attacks...")
    for _ in range(n_bruteforce):
        flows.append(generate_bruteforce_flow())
    
    # Shuffle
    random.shuffle(flows)
    
    df = pd.DataFrame(flows)
    return df


def generate_packet_dataset(flow_df, samples_per_class=1000, sequence_length=100):
    """Generate packet sequences for LSTM training"""
    
    print(f"\nGenerating packet sequences (length={sequence_length})...")
    
    all_packets = []
    
    for label in flow_df['label'].unique():
        label_flows = flow_df[flow_df['label'] == label].to_dict('records')
        
        # Sample flows for this label
        n_samples = min(samples_per_class, len(label_flows))
        sampled_flows = random.sample(label_flows, n_samples)
        
        print(f"  {label}: {n_samples} sequences")
        
        for flow in sampled_flows:
            packets = generate_packet_sequence(flow, sequence_length)
            all_packets.extend(packets)
    
    return pd.DataFrame(all_packets)


def main():
    """Main function to generate and save datasets"""
    
    output_dir = os.path.dirname(os.path.abspath(__file__))
    if 'datasets' not in output_dir:
        output_dir = os.path.join(output_dir, 'datasets')
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate flow dataset
    flow_df = generate_dataset(
        n_normal=15000,
        n_ddos=4000,
        n_portscan=3000,
        n_bruteforce=2000
    )
    
    # Save flow dataset
    flow_path = os.path.join(output_dir, 'sdn_flows.csv')
    flow_df.to_csv(flow_path, index=False)
    print(f"\nSaved flow dataset to: {flow_path}")
    print(f"  Total flows: {len(flow_df)}")
    print(f"  Label distribution:")
    for label, count in flow_df['label'].value_counts().items():
        print(f"    {label}: {count} ({count/len(flow_df)*100:.1f}%)")
    
    # Generate packet sequences
    packet_df = generate_packet_dataset(
        flow_df, 
        samples_per_class=2000,
        sequence_length=100
    )
    
    # Save packet dataset
    packet_path = os.path.join(output_dir, 'sdn_packets.csv')
    packet_df.to_csv(packet_path, index=False)
    print(f"\nSaved packet dataset to: {packet_path}")
    print(f"  Total packets: {len(packet_df)}")
    
    # Create a small test set
    test_flow_df = generate_dataset(
        n_normal=1000,
        n_ddos=300,
        n_portscan=200,
        n_bruteforce=150
    )
    test_path = os.path.join(output_dir, 'sdn_flows_test.csv')
    test_flow_df.to_csv(test_path, index=False)
    print(f"\nSaved test dataset to: {test_path}")
    
    print("\n" + "="*60)
    print("Dataset generation complete!")
    print("="*60)
    
    return flow_df, packet_df


if __name__ == "__main__":
    flow_df, packet_df = main()
