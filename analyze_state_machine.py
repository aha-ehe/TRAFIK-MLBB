from scapy.all import rdpcap, IP, UDP, Raw
import collections

def infer_state_machine(filename, target_ip, target_port):
    print(f"\n--- State Machine Inference for {filename} ---")
    packets = rdpcap(filename)

    # Store command transitions per session
    # Session ID -> [List of Commands]
    sessions = collections.defaultdict(list)

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            payload = pkt[Raw].load

            # Identify direction
            direction = "C->S" if dst == target_ip else "S->C"

            # Parse Header (14 bytes)
            if len(payload) >= 14:
                magic = payload[0]
                cmd = payload[1]
                # Session ID (2-6)
                session_id = payload[2:6]

                # Filter for Game Magic (0x01)
                if magic == 0x01:
                    sessions[session_id].append((direction, cmd))

    # Calculate Transitions
    transitions = collections.defaultdict(int)
    total_transitions = 0

    for session_id, history in sessions.items():
        if len(history) < 2: continue

        for i in range(len(history) - 1):
            current_state = f"{history[i][0]}:{hex(history[i][1])}"
            next_state = f"{history[i+1][0]}:{hex(history[i+1][1])}"

            transitions[(current_state, next_state)] += 1
            total_transitions += 1

    # Print Top Transitions
    print(f"Total Transitions Analyzed: {total_transitions}")
    print("\nTop 10 State Transitions (Current State -> Next State):")
    sorted_trans = sorted(transitions.items(), key=lambda x: x[1], reverse=True)

    for (curr, next_st), count in sorted_trans[:10]:
        prob = (count / total_transitions) * 100
        print(f"{curr} -> {next_st} : {count} ({prob:.2f}%)")

    # Detect Rare Transitions (Potential Anomalies or Error States)
    print("\nRare/Anomalous Transitions (< 0.1%):")
    for (curr, next_st), count in sorted_trans:
        prob = (count / total_transitions) * 100
        if prob < 0.1:
             print(f"{curr} -> {next_st} : {count} ({prob:.4f}%)")

infer_state_machine("nyambung -kembali-ke-game.pcap", "103.157.33.7", 5508)
