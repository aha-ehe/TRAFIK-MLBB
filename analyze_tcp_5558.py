from scapy.all import rdpcap, IP, TCP, UDP
import collections

# Analyze the TCP traffic on port 5558 in the reconnect capture
# Is it a standard TCP handshake? Is it carrying data?
# This could be the 'Layer 4 TCP-PPS' vector the user mentioned:
# If the game server also listens on TCP (maybe for reliable state sync or lobby),
# attacking this port could starve the server's ability to process UDP game packets
# or just overwhelm the network interface/firewall state table.

def deep_analyze_tcp_5558(file_path):
    print(f"Deep analyzing TCP port 5558 traffic in {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    syn_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0
    data_packets = 0
    total_len = 0

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            if sport == 5558 or dport == 5558:
                flags = pkt[TCP].flags
                if 'S' in flags: syn_count += 1
                if 'A' in flags: ack_count += 1
                if 'F' in flags: fin_count += 1
                if 'R' in flags: rst_count += 1

                payload_len = len(pkt[TCP].payload)
                if payload_len > 0:
                    data_packets += 1
                    total_len += payload_len

    print(f"TCP 5558 Stats:")
    print(f" - SYN: {syn_count}")
    print(f" - ACK: {ack_count}")
    print(f" - FIN: {fin_count}")
    print(f" - RST: {rst_count}")
    print(f" - Data Packets: {data_packets}")
    print(f" - Total Data Length: {total_len} bytes")

    if data_packets > 0:
        print("Sample Payload Data (Hex):")
        count = 0
        for pkt in packets:
            if IP in pkt and TCP in pkt and (pkt[TCP].sport == 5558 or pkt[TCP].dport == 5558):
                payload = bytes(pkt[TCP].payload)
                if len(payload) > 0:
                    print(f" - {payload.hex()[:50]}...")
                    count += 1
                    if count >= 5: break

if __name__ == "__main__":
    deep_analyze_tcp_5558('nyambung -kembali-ke-game.pcap')
