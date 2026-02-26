from scapy.all import rdpcap, IP, UDP
import statistics

def analyze_tick_rate(filename, target_ip, target_port):
    print(f"\n--- Tick Rate Analysis of {filename} ---")
    packets = rdpcap(filename)

    server_timestamps = []

    for pkt in packets:
        if IP in pkt and UDP in pkt:
            src = pkt[IP].src
            sport = pkt[UDP].sport

            # Packets FROM server
            if src == target_ip and sport == target_port:
                server_timestamps.append(pkt.time)

    if len(server_timestamps) < 2:
        print("Not enough packets from server to analyze.")
        return

    # Calculate differences
    intervals = []
    for i in range(1, len(server_timestamps)):
        diff = server_timestamps[i] - server_timestamps[i-1]
        # Filter for normal packet intervals (e.g. ignore long pauses/bursts < 1ms)
        if 0.005 < diff < 0.2: # Filter for 5ms - 200ms range
            intervals.append(float(diff))

    if not intervals:
        print("No consistent intervals found.")
        return

    avg_interval = statistics.mean(intervals)
    median_interval = statistics.median(intervals)
    tick_rate = 1.0 / median_interval

    print(f"Median Packet Interval: {median_interval*1000:.2f} ms")
    print(f"Estimated Server Tick Rate: {tick_rate:.2f} Hz")

    # Check consistency
    std_dev = statistics.stdev(intervals)
    print(f"Jitter (Standard Deviation): {std_dev*1000:.2f} ms")

analyze_tick_rate("hasil-awal-game.pcap", "103.157.33.7", 5508)
analyze_tick_rate("nyambung -kembali-ke-game.pcap", "103.157.33.7", 5508)
