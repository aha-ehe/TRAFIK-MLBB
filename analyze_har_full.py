import json
import collections

def analyze_har(filename):
    print(f"\n--- Analyzing HAR: {filename} ---")
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return

    entries = har_data.get('log', {}).get('entries', [])
    print(f"Total Requests: {len(entries)}")

    # Store API Calls
    api_calls = []

    # Domains of interest for MLBB
    # Known: moonton.com, mobilelegends.com, etc.

    for entry in entries:
        req = entry.get('request', {})
        res = entry.get('response', {})
        url = req.get('url', '')
        method = req.get('method', '')
        status = res.get('status', 0)

        # Filter for JSON APIs or Login endpoints
        is_api = "application/json" in res.get('content', {}).get('mimeType', '') or \
                 "login" in url or "auth" in url or "account" in url or "server" in url

        if is_api and status == 200:
            # Extract POST data if available
            post_data = req.get('postData', {}).get('text', '')

            # Extract Response data if available
            res_text = res.get('content', {}).get('text', '')

            api_calls.append({
                'method': method,
                'url': url,
                'request_len': len(post_data),
                'response_len': len(res_text),
                'response_snippet': res_text[:200] if res_text else "No Content"
            })

    print(f"Found {len(api_calls)} potential API calls.")

    print("\n--- Top 10 Interesting API Calls ---")
    for i, call in enumerate(api_calls[:10]):
        print(f"[{i+1}] {call['method']} {call['url']}")
        print(f"    Response: {call['response_snippet']}...")
        print("-" * 40)

    # Search for "Token", "Session", "IP", "Port" in responses
    print("\n--- Searching for Game Server Info (IP/Port) ---")
    for call in api_calls:
        text = call['response_snippet']
        # Look for JSON keys like "ip", "port", "host"
        if '"ip":' in text or '"host":' in text or '"port":' in text:
             print(f"Found IP/Port info in: {call['url']}")
             print(f"Snippet: {text}")

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_har_full.py <har_file>")
        sys.exit(1)

    analyze_har(sys.argv[1])
