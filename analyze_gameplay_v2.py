from scapy.all import rdpcap, IP, UDP, Raw
import collections
import statistics

def analyze_gameplay_deep(filename, target_ip="103.157.33.8", target_port=5513):
    print(f"\n--- Deep Analysis of Gameplay: {filename} ({target_ip}:{target_port}) ---")
    packets = rdpcap(filename)

    server_timestamps = []
    payload_sizes = []

    # Store: {Opcode (1st byte of payload) -> Count}
    cmd_counts = collections.Counter()

    for pkt in packets:
        if IP in pkt and UDP in pkt:
            is_from_server = (pkt[IP].src == target_ip and pkt[UDP].sport == target_port)
            is_to_server = (pkt[IP].dst == target_ip and pkt[UDP].dport == target_port)

            if is_from_server:
                server_timestamps.append(pkt.time)

            if (is_from_server or is_to_server) and Raw in pkt:
                payload = pkt[Raw].load
                payload_sizes.append(len(payload))

                # Check Header (Magic 0x01)
                if len(payload) >= 14 and payload[0] == 0x01:
                    cmd = payload[1]
                    cmd_counts[cmd] += 1

    # Tick Rate Analysis
    if len(server_timestamps) > 10:
        intervals = []
        for i in range(1, len(server_timestamps)):
            diff = server_timestamps[i] - server_timestamps[i-1]
            if 0.005 < diff < 0.2: # Filter valid ticks
                intervals.append(float(diff))

        if intervals:
            median_int = statistics.median(intervals)
            tick_rate = 1.0 / median_int
            print(f"Server Tick Rate: ~{tick_rate:.2f} Hz (Interval: {median_int*1000:.2f} ms)")

    # Command Distribution
    print("\nCommand Distribution:")
    for cmd, count in cmd_counts.most_common(5):
        print(f"Cmd 0x{cmd:02x}: {count} ({count/len(payload_sizes)*100:.2f}%)")

    # Packet Sizes
    if payload_sizes:
        print(f"\nPacket Sizes: Avg={statistics.mean(payload_sizes):.1f}, Median={statistics.median(payload_sizes):.1f}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_gameplay_v2.py <pcap_file>")
        sys.exit(1)

    analyze_gameplay_deep(sys.argv[1])
