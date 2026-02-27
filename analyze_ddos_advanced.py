from scapy.all import rdpcap, IP, UDP, Raw
import collections
import statistics

def advanced_ddos_analysis(filenames):
    print("\n=== Advanced DDoS Vulnerability Analysis ===")

    # Vectors to analyze
    amp_factors = []
    handover_sessions = collections.defaultdict(int)
    voice_packets = 0
    malformed_candidates = 0
    seq_jump_responses = 0

    for filename in filenames:
        print(f"Scanning {filename}...")
        try:
            packets = rdpcap(filename)
        except Exception as e:
            print(f"Skipping {filename}: {e}")
            continue

        # Session tracking for state exhaustion
        current_session = None
        last_seq = 0

        # Requests map for amplification (Seq -> Size)
        requests = {}

        for pkt in packets:
            if IP in pkt and UDP in pkt and Raw in pkt:
                payload = pkt[Raw].load
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # Assume Server IPs based on previous analysis
                is_from_server = src_ip.startswith("103.157") or src_ip.startswith("10.215")
                is_to_server = dst_ip.startswith("103.157") or dst_ip.startswith("10.215")

                if len(payload) >= 14 and payload[0] == 0x01:
                    cmd = payload[1]
                    size = len(pkt) # Full packet size for bandwidth calcs

                    # VECTOR 1: Handshake Amplification (0x71 -> 0x72)
                    # Client sends 0x71 (Small), Server replies 0x72 (Big)
                    if is_to_server and cmd == 0x71:
                        # Track request by session ID (approx)
                        sess_id = payload[2:6]
                        requests[sess_id] = size
                    elif is_from_server and cmd == 0x72:
                        sess_id = payload[2:6]
                        if sess_id in requests:
                            req_size = requests[sess_id]
                            factor = size / req_size
                            amp_factors.append(factor)

                    # VECTOR 2: State Exhaustion (0x75 Handover Loop)
                    # Count consecutive 0x75 without 0x51 (Game Data)
                    if cmd == 0x75:
                        sess_id = payload[2:6]
                        handover_sessions[sess_id] += 1
                    elif cmd == 0x51:
                        sess_id = payload[2:6]
                        # Reset count if game data flows
                        if sess_id in handover_sessions:
                            handover_sessions[sess_id] = 0

                    # VECTOR 3: Invalid Sequence / Window Validation
                    # Look for server responses (0x52 Ack) to out-of-order packets
                    # (Hard to prove without active sending, but look for high Ack to low Seq)

                    # VECTOR 4: Malformed Packet Candidates
                    # Check for inconsistent lengths in header vs payload
                    # (Protocol specific logic: e.g. cmd 0x52 usually 10 bytes payload)
                    if cmd == 0x52 and len(payload) > 50:
                        malformed_candidates += 1

                    # VECTOR 5: Voice/Chat Reflection
                    # Look for IP addresses in payload (ASCII)
                    try:
                        if b"Voice_" in payload or b"203.175." in payload:
                            voice_packets += 1
                    except: pass

    print("\n--- Vulnerability Report ---")

    # Report Vector 1
    if amp_factors:
        avg_amp = statistics.mean(amp_factors)
        max_amp = max(amp_factors)
        print(f"[V1] UDP Amplification (Handshake): Confirmed")
        print(f"     Average Factor: {avg_amp:.2f}x")
        print(f"     Max Factor: {max_amp:.2f}x")
        print(f"     Status: CRITICAL (Reflector Attack)")
    else:
        print("[V1] UDP Amplification: No handshake pairs found in these captures.")

    # Report Vector 2
    stuck_sessions = {k:v for k,v in handover_sessions.items() if v > 100}
    if stuck_sessions:
        print(f"\n[V2] State Exhaustion (Handover Loop): Confirmed")
        print(f"     Sessions stuck in 'Verify' (Cmd 0x75) > 100 packets: {len(stuck_sessions)}")
        print(f"     Max Loop Count: {max(stuck_sessions.values())}")
        print(f"     Status: HIGH (Resource Consumption)")
    else:
        print("\n[V2] State Exhaustion: No stuck sessions found.")

    # Report Vector 3 & 4
    if malformed_candidates > 0:
        print(f"\n[V4] Malformed Packet Fuzzing: Potential")
        print(f"     Suspiciously large 'Ack' packets found: {malformed_candidates}")
        print(f"     Status: MEDIUM (Parser Exploitation)")

    # Report Vector 5
    if voice_packets > 0:
        print(f"\n[V5] Voice Server Reflection: Confirmed")
        print(f"     Packets containing Voice Config/IP: {voice_packets}")
        print(f"     Status: MEDIUM (Secondary Reflector / Info Leak)")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_ddos_advanced.py <pcap_file1> [pcap_file2 ...]")
        sys.exit(1)

    filenames = sys.argv[1:]
    advanced_ddos_analysis(filenames)
