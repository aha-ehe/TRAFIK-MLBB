import json
import base64
import re

# Some of the output looks like binary garbage that just happens to contain the characters "ip" or "tcp".
# But some might be protobuf or custom binary formats.
# Let's try to focus on clean ASCII strings that look like valid IPs or JSON.

def rigorous_analysis(file_path):
    print(f"Rigorous analysis of {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Extract all text fields (both plain and base64 decoded)
    responses = content.split('"response":')

    extracted_texts = []

    for resp in responses[1:]:
        # Extract text content
        match = re.search(r'"text"\s*:\s*"(.*?)"', resp)
        if match:
            text_data = match.group(1)

            # Check encoding
            if '"encoding":"base64"' in resp or '"encoding": "base64"' in resp:
                try:
                    decoded = base64.b64decode(text_data)
                    extracted_texts.append(decoded)
                except:
                    pass
            else:
                # It's plain text, but might be escaped
                try:
                    unescaped = text_data.encode('utf-8').decode('unicode_escape')
                    extracted_texts.append(unescaped.encode('utf-8')) # Keep as bytes for consistent searching
                except:
                    extracted_texts.append(text_data.encode('utf-8'))

    print(f"Collected {len(extracted_texts)} response bodies.")

    # Search for IP patterns (IPv4)
    # \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
    ip_pattern = re.compile(b'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}')

    unique_ips = set()

    for blob in extracted_texts:
        # decode to string for regex search, ignoring errors
        try:
            s = blob.decode('utf-8', errors='ignore')
            ips = ip_pattern.findall(blob)
            for ip in ips:
                ip_str = ip.decode('utf-8')
                # Filter out likely version numbers or false positives
                # Valid IP segments are 0-255
                parts = ip_str.split('.')
                if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                    # Filter out local IPs or obviously wrong ones (like version numbers 1.2.3.4 if consistent)
                    if not ip_str.startswith('127.0.0.1') and not ip_str.startswith('0.'):
                        unique_ips.add(ip_str)
        except:
            pass

    print(f"Found {len(unique_ips)} potential unique IPs.")
    for ip in sorted(list(unique_ips)):
        print(f" - {ip}")

    # Search for "port": 1234 or "port": "1234"
    port_pattern = re.compile(r'"port"\s*:\s*"?(\d+)"?')
    unique_ports = set()

    for blob in extracted_texts:
        try:
            s = blob.decode('utf-8', errors='ignore')
            ports = port_pattern.findall(s)
            for p in ports:
                unique_ports.add(p)
        except:
            pass

    print(f"Found {len(unique_ports)} potential ports specified in JSON.")
    for p in sorted(list(unique_ports)):
        print(f" - {p}")

if __name__ == "__main__":
    rigorous_analysis('login-dari-awal-bagian-1.har')
    print("-" * 30)
    rigorous_analysis('login-dari-awal-bagian-2.har')
