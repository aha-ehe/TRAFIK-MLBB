from scapy.all import rdpcap, IP, UDP, Raw
import collections

def analyze_subcommands(filename, target_ip, target_port):
    print(f"\n--- Sub-command Analysis of {filename} ---")
    packets = rdpcap(filename)

    # Analyze Cmd 0x51 (Game Data)
    # Store: {Opcode (1st byte of payload) -> [Size1, Size2, ...]}
    subcommands = collections.defaultdict(list)

    total_51 = 0

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            if pkt[UDP].dport == target_port or pkt[UDP].sport == target_port:
                payload = pkt[Raw].load
                if len(payload) > 15 and payload[1] == 0x51: # Check Cmd
                    # Assuming Offset 14 is the Opcode/Message Type
                    opcode = payload[14]
                    payload_size = len(payload) - 14
                    subcommands[opcode].append(payload_size)
                    total_51 += 1

    if not total_51:
        print("No Cmd 0x51 packets found.")
        return

    print(f"Total Cmd 0x51 Packets: {total_51}")
    print("\nTop 10 Sub-commands (Opcodes):")

    sorted_ops = sorted(subcommands.items(), key=lambda x: len(x[1]), reverse=True)

    for opcode, sizes in sorted_ops[:10]:
        count = len(sizes)
        freq = (count / total_51) * 100
        avg_size = sum(sizes) / count
        min_size = min(sizes)
        max_size = max(sizes)

        # Heuristic Guess
        guess = "Unknown"
        if freq > 30 and avg_size < 40: guess = "Movement / Heartbeat"
        elif freq < 5 and avg_size > 100: guess = "Skill / Event"
        elif avg_size < 10: guess = "Keep-alive"

        print(f"Opcode: 0x{opcode:02x} | Count: {count} ({freq:5.2f}%) | Size: {avg_size:.1f} ({min_size}-{max_size}) | Type: {guess}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_semantic.py <pcap_file> [target_ip] [target_port]")
        print("Example: python3 analyze_semantic.py game.pcap 103.157.33.7 5508")
        sys.exit(1)

    filename = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else "103.157.33.7"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5508

    analyze_subcommands(filename, ip, port)
