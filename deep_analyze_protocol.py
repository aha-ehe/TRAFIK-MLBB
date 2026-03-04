from scapy.all import rdpcap, IP, UDP, Raw
import binascii
import struct

def parse_header(payload):
    # Based on the previous hex dump:
    # Example 1: 0151c2a94e798d00000066aab62d1f0000004001000015007000f5070132450a7000e3d4daed02021480060180
    # Example 2: 0152c2a94e798e000000ec02149c8d000000400100000000

    # Hypothesis:
    # Byte 0: Magic / Command (01)
    # Byte 1: Sub-command (51, 52, 75, 71, etc.)
    # Bytes 2-5: Session ID or Timestamp? (c2a94e79) -> repeated
    # Bytes 6-9: Sequence Number? (8d000000 -> 141)
    # Bytes 10-13: Acknowledgment Number? (66aab62d)

    if len(payload) < 14:
        return None

    data = {}
    data['magic'] = payload[0]
    data['cmd'] = payload[1]
    data['session_id'] = binascii.hexlify(payload[2:6]).decode()

    # Try unpacking as Little Endian unsigned int
    try:
        data['seq_num'] = struct.unpack('<I', payload[6:10])[0]
        data['ack_num'] = struct.unpack('<I', payload[10:14])[0]
    except:
        data['seq_num'] = -1
        data['ack_num'] = -1

    data['raw_hex'] = binascii.hexlify(payload).decode()
    return data

def deep_analyze(filename, target_ip, target_port):
    print(f"\n--- Deep Analysis of {filename} ---")
    packets = rdpcap(filename)

    outgoing_headers = []
    incoming_headers = []

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            payload = pkt[Raw].load

            parsed = parse_header(payload)
            if not parsed: continue

            if dst == target_ip and dport == target_port:
                outgoing_headers.append(parsed)
            elif src == target_ip and sport == target_port:
                incoming_headers.append(parsed)

    # Analyze Sequence Numbers
    print("Outgoing Packets Analysis:")
    prev_seq = -1
    for i, p in enumerate(outgoing_headers[:10]):
        diff = p['seq_num'] - prev_seq if prev_seq != -1 else 0
        print(f"#{i} CMD: {hex(p['cmd'])} | Sess: {p['session_id']} | Seq: {p['seq_num']} (+{diff}) | Ack: {p['ack_num']}")
        prev_seq = p['seq_num']

    print("\nIncoming Packets Analysis:")
    prev_seq = -1
    for i, p in enumerate(incoming_headers[:10]):
        diff = p['seq_num'] - prev_seq if prev_seq != -1 else 0
        print(f"#{i} CMD: {hex(p['cmd'])} | Sess: {p['session_id']} | Seq: {p['seq_num']} (+{diff}) | Ack: {p['ack_num']}")
        prev_seq = p['seq_num']

    # Compare Session IDs between the two files
    unique_sessions = set(p['session_id'] for p in outgoing_headers)
    print(f"\nUnique Session IDs found in Outgoing: {unique_sessions}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 deep_analyze_protocol.py <pcap_file> [target_ip] [target_port]")
        sys.exit(1)

    filename = sys.argv[1]
    ip = sys.argv[2] if len(sys.argv) > 2 else "103.157.33.7"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5508

    deep_analyze(filename, ip, port)
