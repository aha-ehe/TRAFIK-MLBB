from scapy.all import rdpcap, IP, UDP, Raw
import collections
import struct

def analyze_gameplay(filename, target_port=5508):
    print(f"\n--- Analyzing Gameplay: {filename} ---")
    packets = rdpcap(filename)

    cmd_counts = collections.Counter()
    payload_sizes = []
    coord_triplets = 0

    server_ip = None

    # Identify Server IP (Most frequent destination/source on target port)
    ip_counter = collections.Counter()
    for pkt in packets:
        if IP in pkt and UDP in pkt:
            if pkt[UDP].dport == target_port: ip_counter[pkt[IP].dst] += 1
            if pkt[UDP].sport == target_port: ip_counter[pkt[IP].src] += 1

    if ip_counter:
        server_ip = ip_counter.most_common(1)[0][0]
        print(f"Detected Game Server IP: {server_ip}")
    else:
        print("No traffic on port 5508 found.")
        return

    # Analyze Packet Stream
    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            # Filter for Game Traffic
            is_game = (pkt[IP].src == server_ip and pkt[UDP].sport == target_port) or \
                      (pkt[IP].dst == server_ip and pkt[UDP].dport == target_port)

            if is_game:
                payload = pkt[Raw].load

                # Check Header (Magic 0x01)
                if len(payload) >= 14 and payload[0] == 0x01:
                    cmd = payload[1]
                    cmd_counts[cmd] += 1
                    payload_sizes.append(len(payload))

                    # Scan for coordinates in Cmd 0x51
                    if cmd == 0x51 and len(payload) > 30:
                        content = payload[14:]
                        # Simple heuristic: scan for sequences of 3 floats
                        for i in range(len(content) - 12):
                            try:
                                floats = struct.unpack('<3f', content[i:i+12])
                                x, y, z = floats
                                # Dynamic range check for active gameplay
                                # X, Z likely map coordinates, Y likely height (often small/stable)
                                if (abs(x) > 1.0 and abs(x) < 500.0) and \
                                   (abs(z) > 1.0 and abs(z) < 500.0) and \
                                   (abs(y) < 100.0):
                                     coord_triplets += 1
                            except: pass

    print("\nCommand Distribution:")
    for cmd, count in cmd_counts.most_common(5):
        print(f"Cmd 0x{cmd:02x}: {count} ({count/len(payload_sizes)*100:.2f}%)")

    print(f"\nPotential Coordinate Updates Found: {coord_triplets}")

    if payload_sizes:
        import statistics
        print(f"Average Packet Size: {statistics.mean(payload_sizes):.2f} bytes")
        print(f"Median Packet Size: {statistics.median(payload_sizes):.2f} bytes")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_gameplay.py <pcap_file> [target_port]")
        sys.exit(1)

    filename = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5508

    analyze_gameplay(filename, port)
