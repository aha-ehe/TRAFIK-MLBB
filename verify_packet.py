from scapy.all import rdpcap, IP, UDP, Raw
import struct
import binascii

class MobileLegendsPacket:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.magic = 0
        self.command = 0
        self.session_id = 0
        self.seq_num = 0
        self.ack_num = 0
        self.payload = b""
        self.is_valid = False
        self.parse()

    def parse(self):
        if len(self.raw_data) < 14:
            return

        # Header Structure (Hypothetical based on reverse engineering)
        # 0: Magic (1 byte)
        # 1: Command (1 byte)
        # 2-5: Session ID (4 bytes)
        # 6-9: Sequence Number (4 bytes, Little Endian)
        # 10-13: Ack Number (4 bytes, Little Endian)

        try:
            self.magic = self.raw_data[0]
            self.command = self.raw_data[1]
            self.session_id = binascii.hexlify(self.raw_data[2:6]).decode() # Keep as hex string
            self.seq_num = struct.unpack('<I', self.raw_data[6:10])[0]
            self.ack_num = struct.unpack('<I', self.raw_data[10:14])[0]
            self.payload = self.raw_data[14:]
            self.is_valid = True
        except Exception as e:
            print(f"Error parsing packet: {e}")

    def __str__(self):
        if not self.is_valid:
            return "Invalid Packet"
        return (f"Magic: {hex(self.magic)} | Cmd: {hex(self.command)} | "
                f"Session: {self.session_id} | Seq: {self.seq_num} | Ack: {self.ack_num} | "
                f"Payload Size: {len(self.payload)} bytes")

def verify_structure(filename):
    print(f"Verifying packet structure in {filename}...")
    packets = rdpcap(filename)
    valid_count = 0
    total_count = 0

    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            # Filter for game port 5508
            if pkt[UDP].dport == 5508 or pkt[UDP].sport == 5508:
                total_count += 1
                ml_pkt = MobileLegendsPacket(pkt[Raw].load)
                if ml_pkt.is_valid and ml_pkt.magic == 0x01:
                    valid_count += 1
                    if valid_count <= 5: # Print first 5 valid packets
                        print(ml_pkt)

    print(f"Total UDP Game Packets: {total_count}")
    print(f"Valid Header Matches (Magic 0x01): {valid_count}")
    print(f"Match Rate: {valid_count/total_count*100:.2f}%")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 verify_packet.py <pcap_file>")
        sys.exit(1)

    verify_structure(sys.argv[1])
