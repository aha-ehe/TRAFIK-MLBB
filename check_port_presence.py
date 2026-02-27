from scapy.all import rdpcap, IP, TCP, UDP
import collections

# It seems the TCP port 5558 is definitely used in the reconnect phase (maybe for reliable game state sync)
# while the UDP port 5508 is used for the main game loop.
# The payload starts with `000000xx`, likely a length prefix, suggesting a custom framing protocol over TCP.

# Let's check if the main game pcap has ANY traffic to port 5558
# The user said "hasil-awal-game.pcap" is the game traffic.
# If TCP 5558 is NOT used during normal gameplay, but IS open, then it's a prime attack vector.
# If it IS used, attacking it would disrupt the game state sync, causing "freeze" or "reconnecting" behavior
# but potentially leaving the UDP stream alive (ping might spike if the client tries to compensate or if the server
# prioritizes TCP processing).

def check_tcp_port_presence(file_path, port):
    print(f"Checking for Port {port} presence in {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    found = False
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            if pkt[TCP].sport == port or pkt[TCP].dport == port:
                found = True
                break

    if found:
        print(f"TCP Port {port} IS present in this capture.")
    else:
        print(f"TCP Port {port} is NOT present in this capture.")

if __name__ == "__main__":
    check_tcp_port_presence('hasil-awal-game.pcap', 5558)
