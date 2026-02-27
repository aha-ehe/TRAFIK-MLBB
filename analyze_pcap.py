from scapy.all import rdpcap, IP, TCP, UDP
import collections

def analyze_pcap(file_path):
    print(f"Reading {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    print(f"Total packets: {len(packets)}")

    ip_counts = collections.defaultdict(int)
    protocol_counts = collections.defaultdict(int)
    port_counts = collections.defaultdict(int)

    tcp_connections = set()
    udp_flows = set()

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto

            ip_counts[src_ip] += 1
            ip_counts[dst_ip] += 1

            if TCP in pkt:
                protocol_counts['TCP'] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                port_counts[sport] += 1
                port_counts[dport] += 1
                tcp_connections.add(tuple(sorted(((src_ip, sport), (dst_ip, dport)))))
            elif UDP in pkt:
                protocol_counts['UDP'] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                port_counts[sport] += 1
                port_counts[dport] += 1
                udp_flows.add(tuple(sorted(((src_ip, sport), (dst_ip, dport)))))
            else:
                protocol_counts[f'Proto-{proto}'] += 1

    print("\nProtocol Distribution:")
    for proto, count in protocol_counts.items():
        print(f" - {proto}: {count}")

    print("\nTop 5 Talkers (IPs):")
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_ips:
        print(f" - {ip}: {count}")

    print("\nTop 5 Ports:")
    sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for port, count in sorted_ports:
        print(f" - {port}: {count}")

    print(f"\nUnique TCP Connections: {len(tcp_connections)}")
    print(f"Unique UDP Flows: {len(udp_flows)}")

    # Identify likely Game Server (UDP high volume)
    # Usually game traffic is UDP and involves a specific server IP
    if protocol_counts['UDP'] > 100:
        print("\nLikely Game Server Candidates (UDP):")
        # Find the flow with the most packets
        flow_counts = collections.defaultdict(int)
        for pkt in packets:
             if IP in pkt and UDP in pkt:
                 src = (pkt[IP].src, pkt[UDP].sport)
                 dst = (pkt[IP].dst, pkt[UDP].dport)
                 flow = tuple(sorted((src, dst)))
                 flow_counts[flow] += 1

        sorted_flows = sorted(flow_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for flow, count in sorted_flows:
            print(f" - {flow}: {count} packets")

if __name__ == "__main__":
    analyze_pcap('hasil-awal-game.pcap')
    print("-" * 30)
    analyze_pcap('nyambung -kembali-ke-game.pcap')
