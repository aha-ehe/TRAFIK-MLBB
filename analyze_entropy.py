from scapy.all import rdpcap, IP, UDP, Raw
import math
import collections

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def analyze_entropy_and_strings(filename, target_ip, target_port):
    print(f"\n--- Deep Entropy & String Analysis of {filename} ---")
    packets = rdpcap(filename)

    total_entropy = 0
    payload_count = 0
    strings_found = []

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            if pkt[UDP].dport == target_port or pkt[UDP].sport == target_port:
                payload = pkt[Raw].load

                # Assume 14-byte header
                if len(payload) > 14:
                    data = payload[14:]
                    entropy = shannon_entropy(data)
                    total_entropy += entropy
                    payload_count += 1

                    # Simple ASCII string search (min length 4)
                    try:
                        decoded = data.decode('ascii', errors='ignore')
                        # Filter for meaningful strings (alphanumeric sequences > 4 chars)
                        clean_str = "".join([c if c.isalnum() or c in "._-" else " " for c in decoded])
                        words = [w for w in clean_str.split() if len(w) > 4]
                        strings_found.extend(words)
                    except:
                        pass

    if payload_count > 0:
        avg_entropy = total_entropy / payload_count
        print(f"Average Payload Entropy: {avg_entropy:.4f} bits/byte")
        if avg_entropy > 7.5:
            print("Verdict: High Entropy -> Likely Encrypted or Compressed.")
        else:
            print("Verdict: Low/Medium Entropy -> Likely Unencrypted or structured binary.")

    # Count most common strings
    counter = collections.Counter(strings_found)
    print("\nTop 10 Strings Found in Payloads:")
    for string, count in counter.most_common(10):
        print(f"{string}: {count}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_entropy.py <pcap_file> [target_ip] [target_port]")
        sys.exit(1)

    filename = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else "103.157.33.7"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5508

    analyze_entropy_and_strings(filename, ip, port)
