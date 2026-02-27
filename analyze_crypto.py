from scapy.all import rdpcap, IP, UDP, Raw
import collections

def xor_bytes(data, key):
    return bytes(a ^ b for a, b in zip(data, key))

def analyze_xor_keys(filename, target_ip, target_port):
    print(f"\n--- XOR / Bitwise Decryption Analysis of {filename} ---")
    packets = rdpcap(filename)

    # Focus on packets with CMD 0x51 (Game Data)
    payloads = []

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            if pkt[UDP].dport == target_port or pkt[UDP].sport == target_port:
                payload = pkt[Raw].load
                if len(payload) > 18 and payload[1] == 0x51:
                    payloads.append(payload[14:]) # Skip header

    if not payloads:
        print("No CMD 0x51 packets found for analysis.")
        return

    print(f"Analyzing {len(payloads)} payloads for XOR patterns...")

    # Method 1: Check if the first byte is an XOR key (assuming first plaintext byte is 0x00)
    potential_keys = []
    for p in payloads:
        # Assumption: Plaintext starts with 0x00 or similar low value
        # Key = Ciphertext ^ Plaintext (0x00) => Key = Ciphertext
        potential_keys.append(p[0])

    key_counter = collections.Counter(potential_keys)
    print("\nPotential 1-byte XOR Keys (assuming first byte is 0x00):")
    for k, count in key_counter.most_common(5):
        print(f"Key: 0x{k:02x} | Count: {count}")

    # Method 2: Check for Session ID as XOR Key
    # (Requires access to session ID from header, omitted for brevity as previous step showed cleartext structs)

    # Method 3: Bitwise NOT check
    # Sometimes data is just inverted
    inverted_first_bytes = [~b & 0xFF for b in potential_keys]
    inv_counter = collections.Counter(inverted_first_bytes)
    print("\nMost common Inverted bytes:")
    for k, count in inv_counter.most_common(5):
         print(f"Inv: 0x{k:02x} | Count: {count}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_crypto.py <pcap_file> [target_ip] [target_port]")
        sys.exit(1)

    filename = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else "103.157.33.7"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5508

    analyze_xor_keys(filename, ip, port)
