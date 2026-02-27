from scapy.all import rdpcap, IP, UDP, Raw
import struct
import collections

def scan_for_coordinates(filename, target_ip, target_port):
    print(f"\n--- Coordinate Scanning (Float32) of {filename} ---")
    packets = rdpcap(filename)

    # Analyze Cmd 0x51 (Game Data)
    possible_coords = []

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            if pkt[UDP].dport == target_port or pkt[UDP].sport == target_port:
                payload = pkt[Raw].load
                if len(payload) > 30: # Need at least 12 bytes for 3 floats
                    content = payload[14:] # Skip header

                    # Scan for sequences of 3 floats that look like coordinates
                    # Assumptions:
                    # - Values within reasonable game map range (e.g. -500 to 500)
                    # - Non-zero
                    # - Float32 (4 bytes each)

                    for i in range(len(content) - 12):
                        try:
                            floats = struct.unpack('<3f', content[i:i+12])
                            x, y, z = floats

                            # Filter for reasonable game coordinates
                            # Mobile Legends map likely uses large coordinates or small, normalized ones.
                            # Let's look for "movement" - small changes in value.
                            # But for a single packet, we check range.

                            # Heuristic: Coordinates usually aren't huge integers, nor tiny decimals (e.g. 1e-10)
                            if (abs(x) > 0.1 and abs(x) < 5000) and \
                               (abs(y) > 0.1 and abs(y) < 5000) and \
                               (abs(z) > 0.1 and abs(z) < 5000):

                                # Y often represents height and is usually close to 0 or constant in MOBA
                                if abs(y) < 100:
                                    possible_coords.append((x, y, z))
                        except:
                            pass

    if not possible_coords:
        print("No coordinate-like float sequences found.")
        return

    print(f"Found {len(possible_coords)} potential coordinate triplets.")
    print("Sample of first 5 unique potential coordinates:")
    seen = set()
    count = 0
    for c in possible_coords:
        if c not in seen:
            print(f"({c[0]:.2f}, {c[1]:.2f}, {c[2]:.2f})")
            seen.add(c)
            count += 1
            if count >= 5: break

scan_for_coordinates("hasil-awal-game.pcap", "103.157.33.7", 5508)
scan_for_coordinates("nyambung -kembali-ke-game.pcap", "103.157.33.7", 5508)
