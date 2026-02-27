from scapy.all import rdpcap, IP, UDP, Raw
import collections
import statistics

def advanced_fuzzing_analysis(filenames):
    print("\n=== Advanced Engineering Vulnerability Analysis ===")

    # Storage for analysis
    ttl_values = collections.Counter()
    payload_lengths = []
    checksum_zeros = 0
    fragmented_packets = 0
    total_packets = 0

    # Store: {Command -> [Payload Sizes]}
    cmd_sizes = collections.defaultdict(list)

    for filename in filenames:
        print(f"Analyzing {filename}...")
        try:
            packets = rdpcap(filename)
        except Exception as e:
            print(f"Skipping {filename}: {e}")
            continue

        for pkt in packets:
            if IP in pkt and UDP in pkt:
                total_packets += 1

                # Check 1: TTL Distribution (Resource Consumption)
                ttl_values[pkt[IP].ttl] += 1

                # Check 2: IP Fragmentation (Reassembly Buffer Exhaustion)
                if pkt[IP].flags == 1 or pkt[IP].frag > 0: # MF flag or offset > 0
                    fragmented_packets += 1

                # Check 3: UDP Checksum Bypass (Integrity)
                if pkt[UDP].chksum == 0:
                    checksum_zeros += 1

                if Raw in pkt:
                    payload = pkt[Raw].load
                    payload_lengths.append(len(payload))

                    if len(payload) > 1 and payload[0] == 0x01:
                        cmd = payload[1]
                        cmd_sizes[cmd].append(len(payload))

    print("\n--- Engineering Vulnerability Report ---")

    # Report Vector 6: Checksum Integrity
    chksum_rate = (checksum_zeros / total_packets) * 100 if total_packets > 0 else 0
    print(f"[V6] UDP Checksum Bypass: {'Confirmed' if chksum_rate > 5 else 'Low Risk'}")
    print(f"     Zero Checksum Rate: {chksum_rate:.2f}% ({checksum_zeros}/{total_packets})")
    print(f"     Risk: Attackers can flip bits in transit without detection if app layer CRC is weak.")

    # Report Vector 7: IP Fragmentation Reassembly
    frag_rate = (fragmented_packets / total_packets) * 100 if total_packets > 0 else 0
    print(f"\n[V7] IP Fragmentation Reassembly Exhaustion: {'Confirmed' if frag_rate > 0 else 'Theoretical'}")
    print(f"     Fragmented Packets Found: {fragmented_packets} ({frag_rate:.2f}%)")
    print(f"     Risk: Sending incomplete fragments forces server to hold buffer until timeout (DoS).")

    # Report Vector 8: TTL Resource Consumption
    print(f"\n[V8] TTL Expiry Resource Consumption (ICMP Generation): Potential")
    print(f"     TTL Distribution: {ttl_values.most_common(5)}")
    low_ttl = sum(c for t, c in ttl_values.items() if t < 10)
    print(f"     Low TTL (<10) Count: {low_ttl}")
    print(f"     Risk: Forced ICMP Time Exceeded generation wastes CPU cycles.")

    # Report Vector 9: Payload Size Anomalies (Buffer Overflow Fuzzing)
    print(f"\n[V9] Payload Size Anomaly Detection (Fuzzing Targets):")
    for cmd, sizes in cmd_sizes.items():
        avg = statistics.mean(sizes)
        std_dev = statistics.stdev(sizes) if len(sizes) > 1 else 0
        max_size = max(sizes)

        # Anomaly: Packet > Average + 3*StdDev
        anomalies = [s for s in sizes if s > avg + (3 * std_dev)]
        if anomalies:
             print(f"     Cmd 0x{cmd:02x}: Avg={avg:.1f}, Max={max_size}. Anomalies Found: {len(anomalies)}")
             print(f"     -> Potential Buffer Overflow Target: Cmd 0x{cmd:02x} accepts variable sizes up to {max_size} bytes.")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_engineering.py <pcap_file1> [pcap_file2 ...]")
        sys.exit(1)

    filenames = sys.argv[1:]
    advanced_fuzzing_analysis(filenames)
