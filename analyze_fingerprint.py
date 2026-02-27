from scapy.all import rdpcap, IP, UDP, Raw
import collections

def visualize_byte_frequency(filename, target_ip, target_port):
    print(f"\n--- Statistical Fingerprint of {filename} ---")
    packets = rdpcap(filename)

    # Analyze first 32 bytes of payload
    byte_counts = collections.defaultdict(collections.Counter)
    payload_count = 0

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            if pkt[UDP].dport == target_port or pkt[UDP].sport == target_port:
                payload = pkt[Raw].load
                # Skip header (14 bytes), focus on content
                if len(payload) > 14:
                    content = payload[14:]
                    for i in range(min(len(content), 32)):
                        byte_counts[i][content[i]] += 1
                    payload_count += 1

    if payload_count == 0:
        return

    print(f"Analyzed {payload_count} packets. Byte distribution (0-32 after header):")
    print("Offset | Dominant Byte (Hex) | Frequency (%) | Shannon Entropy")
    print("-" * 65)

    import math

    for i in range(32):
        counter = byte_counts[i]
        if not counter: continue

        most_common = counter.most_common(1)
        byte_val, count = most_common[0]
        freq = (count / payload_count) * 100

        # Calculate entropy for this position
        entropy = 0
        for b, c in counter.items():
            p = c / payload_count
            entropy -= p * math.log(p, 2)

        byte_hex = f"0x{byte_val:02x}"
        bar = "#" * int(freq / 5)

        print(f"{i:02d}     | {byte_hex}                | {freq:6.2f}%      | {entropy:.2f}")

visualize_byte_frequency("hasil-awal-game.pcap", "103.157.33.7", 5508)
visualize_byte_frequency("nyambung -kembali-ke-game.pcap", "103.157.33.7", 5508)
