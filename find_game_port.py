from scapy.all import rdpcap, IP, UDP
import collections

def find_top_udp_ports(filename):
    print(f"\n--- Identifying Top UDP Ports in {filename} ---")
    packets = rdpcap(filename)

    # Store: (IP, Port) -> Count
    udp_dest = collections.Counter()
    udp_src = collections.Counter()

    for pkt in packets:
        if IP in pkt and UDP in pkt:
            udp_dest[(pkt[IP].dst, pkt[UDP].dport)] += 1
            udp_src[(pkt[IP].src, pkt[UDP].sport)] += 1

    print("Top 5 Destination (IP:Port):")
    for (ip, port), count in udp_dest.most_common(5):
        print(f"  {ip}:{port} -> {count} packets")

    print("\nTop 5 Source (IP:Port):")
    for (ip, port), count in udp_src.most_common(5):
        print(f"  {ip}:{port} -> {count} packets")

find_top_udp_ports("external_repo/saat-dalam-pertandingan.pcap")
