import json
import sys

def analyze_har(file_path):
    print(f"Analyzing {file_path}...")
    try:
        # Try reading line by line if full json load fails,
        # or just read the whole content and try to fix the end if it is truncated.
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Attempt to fix truncated JSON for the first file
        if file_path == 'login-dari-awal-bagian-1.har':
             # The error "Unterminated string" usually means the file was cut off.
             # We can try to find the last valid object or just parse what we can by finding the last closing bracket of the "entries" array if possible.
             # However, since HAR is a big JSON object, we might just need to close the open structures.
             # Let's try to verify if it ends with "]}" or "]}".
             if not content.strip().endswith('}'):
                 print("File seems truncated. Attempting to recover valid JSON entries...")
                 # We can try to extract "entries": [ ... ] manually.
                 start_idx = content.find('"entries":[')
                 if start_idx != -1:
                     entries_content = content[start_idx + 11:]
                     # This is a bit hacky, but let's try to split by "},{" to get individual entries
                     # This won't work perfectly if there are nested objects, but it is a start.
                     # Better approach: Iterate and parse individual objects.
                     pass

    except Exception as e:
        print(f"Error reading file manually: {e}")

    # Let's try to use a streaming parser or just robustly handle errors.
    # Since we only need to extract URLs and responses, maybe we can just regex for them.

    import re
    print("Using regex extraction...")

    urls = re.findall(r'"url":"(http[^"]+)"', content)
    unique_domains = set()
    from urllib.parse import urlparse

    for url in urls:
        try:
            parsed = urlparse(url)
            unique_domains.add(parsed.netloc)
        except:
            pass

    print(f"Unique domains found (regex): {len(unique_domains)}")
    for d in list(unique_domains)[:10]:
        print(f" - {d}")

    # Look for response content that looks like game server info
    # Pattern: "ip":"x.x.x.x" or "port":1234
    potential_ips = re.findall(r'"ip":"(\d+\.\d+\.\d+\.\d+)"', content)
    potential_ports = re.findall(r'"port":(\d+)', content)

    print(f"Potential IPs found in content: {len(potential_ips)}")
    print(list(set(potential_ips))[:10])

    print(f"Potential Ports found in content: {len(potential_ports)}")
    print(list(set(potential_ports))[:10])

    # Search for specific terms like "server", "battle", "room"
    matches = re.findall(r'(".{0,20}(?:server|battle|room).{0,20}":\s*\{[^}]+\})', content)
    print(f"Context matches for 'server/battle/room': {len(matches)}")
    for m in matches[:5]:
        print(f"Match: {m[:200]}...")

if __name__ == "__main__":
    analyze_har('login-dari-awal-bagian-1.har')
    print("-" * 30)
    analyze_har('login-dari-awal-bagian-2.har')
