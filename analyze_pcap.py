from scapy.all import rdpcap, IP, UDP, TCP, DNS

def analyze_pcap(filename):
    print(f"Analyzing {filename}...")
    packets = rdpcap(filename)

    ip_counter = {}
    protocol_counter = {}

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto

            # protocol mapping
            proto_name = "Other"
            if proto == 6: proto_name = "TCP"
            elif proto == 17: proto_name = "UDP"
            elif proto == 1: proto_name = "ICMP"

            protocol_counter[proto_name] = protocol_counter.get(proto_name, 0) + 1

            # Simple IP count to find the most frequent server
            if src not in ip_counter: ip_counter[src] = 0
            if dst not in ip_counter: ip_counter[dst] = 0
            ip_counter[src] += 1
            ip_counter[dst] += 1

    print("Protocol Distribution:", protocol_counter)

    # Sort IPs by frequency to identify the game server
    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
    print("Top 5 IPs involved:", sorted_ips[:5])

    # Extract UDP conversations to see potential game traffic
    udp_convos = {}
    for pkt in packets:
        if UDP in pkt and IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            # Create a unique key for the conversation (sorted to handle bidirectional)
            key = tuple(sorted([(src, sport), (dst, dport)]))
            if key not in udp_convos:
                udp_convos[key] = 0
            udp_convos[key] += 1

    print("\nTop UDP Conversations:")
    sorted_udp = sorted(udp_convos.items(), key=lambda x: x[1], reverse=True)
    for convo, count in sorted_udp[:5]:
        print(f"{convo}: {count} packets")

print("\n--- Analysis of Initial Game ---")
analyze_pcap("hasil-awal-game.pcap")

print("\n--- Analysis of Reconnect ---")
analyze_pcap("nyambung -kembali-ke-game.pcap")
