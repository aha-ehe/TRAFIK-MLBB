from scapy.all import rdpcap, IP, UDP, Raw
import binascii

def analyze_amplification(filename, target_ip, target_port):
    print(f"Analyzing {filename} for amplification...")
    packets = rdpcap(filename)

    requests = {}

    for pkt in packets:
        if IP in pkt and UDP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            len_pkt = len(pkt)

            # Outgoing (Request)
            if dst == target_ip and dport == target_port:
                # Approximate tracking by sequence number if available
                if Raw in pkt:
                     # Using seq number as ID (bytes 6-10)
                     payload = pkt[Raw].load
                     if len(payload) >= 10:
                        seq = payload[6:10]
                        requests[seq] = len_pkt

            # Incoming (Response)
            elif src == target_ip and sport == target_port:
                if Raw in pkt:
                     payload = pkt[Raw].load
                     if len(payload) >= 14:
                        ack = payload[10:14] # Ack number usually matches Request Seq
                        if ack in requests:
                            req_len = requests[ack]
                            amp_factor = len_pkt / req_len
                            if amp_factor > 5: # Flag significant amplification
                                print(f"Potential Amplification! Req Size: {req_len}, Resp Size: {len_pkt}, Factor: {amp_factor:.2f}x")

analyze_amplification("hasil-awal-game.pcap", "103.157.33.7", 5508)
analyze_amplification("nyambung -kembali-ke-game.pcap", "103.157.33.7", 5508)
