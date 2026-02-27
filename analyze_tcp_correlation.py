from scapy.all import rdpcap, IP, TCP, UDP
import collections

GAME_SERVER_IP = "103.157.33.7"

def analyze_targeted_traffic(file_path):
    print(f"Checking for TCP traffic to/from {GAME_SERVER_IP} in {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    tcp_count = 0
    udp_count = 0
    other_count = 0

    tcp_ports = collections.defaultdict(int)

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            if src == GAME_SERVER_IP or dst == GAME_SERVER_IP:
                if TCP in pkt:
                    tcp_count += 1
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    if src == GAME_SERVER_IP:
                        tcp_ports[sport] += 1
                    else:
                        tcp_ports[dport] += 1
                elif UDP in pkt:
                    udp_count += 1
                else:
                    other_count += 1

    print(f"Traffic with {GAME_SERVER_IP}:")
    print(f" - TCP Packets: {tcp_count}")
    print(f" - UDP Packets: {udp_count}")
    print(f" - Other Packets: {other_count}")

    if tcp_count > 0:
        print("TCP Ports observed on Game Server:")
        for port, count in tcp_ports.items():
            print(f" - Port {port}: {count} packets")
    else:
        print("No TCP traffic observed with the Game Server directly.")

    # Check for other significant IPs that might be related to the game infrastructure
    # and DO have TCP traffic.
    print("\nChecking for other significant TCP flows...")
    tcp_flows = collections.defaultdict(int)
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            # Filter out local traffic if possible, but 10.x.x.x is private, so we keep it as client
            # We want to see what public IPs are being talked to over TCP
            if not src.startswith("10."):
                 server_ip = src
                 port = pkt[TCP].sport
            elif not dst.startswith("10."):
                 server_ip = dst
                 port = pkt[TCP].dport
            else:
                 continue

            tcp_flows[(server_ip, port)] += 1

    sorted_tcp = sorted(tcp_flows.items(), key=lambda x: x[1], reverse=True)[:5]
    for (ip, port), count in sorted_tcp:
        print(f" - {ip}:{port} : {count} packets")

if __name__ == "__main__":
    analyze_targeted_traffic('hasil-awal-game.pcap')
    print("-" * 30)
    analyze_targeted_traffic('nyambung -kembali-ke-game.pcap')
