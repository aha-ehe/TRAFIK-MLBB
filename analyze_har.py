import json
import sys

def analyze_har(file_path):
    print(f"Analyzing {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    entries = har_data['log']['entries']
    print(f"Total entries: {len(entries)}")

    servers = set()
    game_server_candidates = []

    for entry in entries:
        request = entry['request']
        url = request['url']
        method = request['method']

        # Identify domains
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        servers.add(domain)

        # Look for potential game server handoff
        response = entry.get('response', {})
        content = response.get('content', {})
        mime_type = content.get('mimeType', '')
        text = content.get('text', '')

        if 'json' in mime_type and text:
            try:
                # Basic heuristic: look for IP addresses or ports in JSON responses
                # This is a broad search for now.
                if '"ip":' in text or '"port":' in text or '"server":' in text:
                     game_server_candidates.append({
                        'url': url,
                        'method': method,
                        'response_sample': text[:200] + "..." if len(text) > 200 else text
                     })
            except:
                pass

    print(f"Unique domains contacted: {len(servers)}")
    for server in list(servers)[:10]: # Print first 10
        print(f" - {server}")

    print(f"\nPotential Game Server Handoffs found: {len(game_server_candidates)}")
    for candidate in game_server_candidates[:5]:
        print(f"URL: {candidate['url']}")
        print(f"Sample: {candidate['response_sample']}\n")

if __name__ == "__main__":
    analyze_har('login-dari-awal-bagian-1.har')
    print("-" * 30)
    analyze_har('login-dari-awal-bagian-2.har')
