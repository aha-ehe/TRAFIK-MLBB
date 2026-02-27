from scapy.all import rdpcap, IP, UDP, Raw
import struct
import collections

def analyze_stability(filename, target_ip, target_port):
    print(f"\n--- Network Stability Analysis of {filename} ---")
    packets = rdpcap(filename)

    server_seqs = []

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            payload = pkt[Raw].load

            # Analyze Server -> Client (Downlink)
            if src == target_ip and sport == target_port:
                if len(payload) >= 14:
                     seq_num = struct.unpack('<I', payload[6:10])[0]
                     server_seqs.append(seq_num)

    if not server_seqs:
        print("No server packets found.")
        return

    # Calculate Loss
    total_packets = len(server_seqs)

    # Sort and remove duplicates (retransmissions)
    unique_seqs = sorted(list(set(server_seqs)))
    if not unique_seqs: return

    min_seq = unique_seqs[0]
    max_seq = unique_seqs[-1]
    expected_packets = max_seq - min_seq + 1

    # Handle wrap-around or reset?
    # Simple check: if max_seq is huge and min is small but gap is massive, might be reset.
    # For now assume continuous session or take the longest continuous segment.

    missing = expected_packets - len(unique_seqs)
    loss_rate = (missing / expected_packets) * 100 if expected_packets > 0 else 0

    print(f"Packets Received: {total_packets}")
    print(f"Unique Sequences: {len(unique_seqs)}")
    print(f"Sequence Range: {min_seq} - {max_seq}")
    print(f"Estimated Packet Loss: {loss_rate:.2f}% (Note: High % may indicate session reset/new game)")

    # Burst Analysis
    # (Simple logic: sequence of packets with very close timestamps)
    # Using timestamps requires the packet objects again, skipped for brevity in this specific script.

analyze_stability("hasil-awal-game.pcap", "103.157.33.7", 5508)
analyze_stability("nyambung -kembali-ke-game.pcap", "103.157.33.7", 5508)
