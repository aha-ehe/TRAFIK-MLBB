from scapy.all import rdpcap, IP, UDP, Raw
import binascii

def analyze_udp_payload(filename, target_ip, target_port):
    print(f"Analyzing UDP payloads in {filename} for {target_ip}:{target_port}...")
    packets = rdpcap(filename)

    outgoing_payloads = []
    incoming_payloads = []

    for pkt in packets:
        if IP in pkt and UDP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport

            if (dst == target_ip and dport == target_port) or (src == target_ip and sport == target_port):
                if Raw in pkt:
                    payload = pkt[Raw].load
                    if dst == target_ip:
                        outgoing_payloads.append(payload)
                    else:
                        incoming_payloads.append(payload)

    print(f"Captured {len(outgoing_payloads)} outgoing and {len(incoming_payloads)} incoming payloads.")

    if outgoing_payloads:
        print("\n--- First 5 Outgoing Payloads (Hex) ---")
        for i, p in enumerate(outgoing_payloads[:5]):
            print(f"{i+1}: {binascii.hexlify(p).decode()}")

    if incoming_payloads:
        print("\n--- First 5 Incoming Payloads (Hex) ---")
        for i, p in enumerate(incoming_payloads[:5]):
            print(f"{i+1}: {binascii.hexlify(p).decode()}")

    # Simple Magic Byte Detection
    if outgoing_payloads:
        first_bytes = [p[:2] for p in outgoing_payloads if len(p) >= 2]
        if first_bytes:
            common = max(set(first_bytes), key=first_bytes.count)
            print(f"\nMost common first 2 bytes (Outgoing): {binascii.hexlify(common).decode()}")

    if incoming_payloads:
        first_bytes = [p[:2] for p in incoming_payloads if len(p) >= 2]
        if first_bytes:
            common = max(set(first_bytes), key=first_bytes.count)
            print(f"Most common first 2 bytes (Incoming): {binascii.hexlify(common).decode()}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_payload.py <pcap_file> [target_ip] [target_port]")
        sys.exit(1)

    filename = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else "103.157.33.7"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5508

    analyze_udp_payload(filename, ip, port)
