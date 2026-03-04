from scapy.all import rdpcap, IP, UDP, Raw
import binascii
import struct

def analyze_handshake_flow(filename, target_ip, target_port):
    print(f"\n--- Detailed Handshake Flow Analysis of {filename} ---")
    packets = rdpcap(filename)

    count = 0

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            payload = pkt[Raw].load

            # Filter for game traffic
            if (dst == target_ip and dport == target_port) or (src == target_ip and sport == target_port):
                count += 1
                if count > 10: break # Only analyze the first 10 packets of the session

                direction = "Client -> Server" if dst == target_ip else "Server -> Client"

                # Parse header
                if len(payload) >= 14:
                    magic = payload[0]
                    cmd = payload[1]
                    session_id = binascii.hexlify(payload[2:6]).decode()
                    seq_num = struct.unpack('<I', payload[6:10])[0]
                    ack_num = struct.unpack('<I', payload[10:14])[0]

                    print(f"[{count}] {direction}")
                    print(f"    CMD: {hex(cmd)} | Session: {session_id} | Seq: {seq_num} | Ack: {ack_num}")
                    print(f"    Payload (First 32 bytes): {binascii.hexlify(payload[14:46]).decode()}")

                    # Look for potential text strings in payload
                    try:
                        text = payload[14:].decode('utf-8', errors='ignore')
                        clean_text = "".join([c if c.isalnum() else "." for c in text])
                        if len(clean_text) > 4:
                            print(f"    Potential Text: {clean_text[:50]}...")
                    except:
                        pass
                    print("-" * 40)

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_handshake.py <pcap_file> [target_ip] [target_port]")
        sys.exit(1)

    filename = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else "103.157.33.7"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5508

    analyze_handshake_flow(filename, ip, port)
