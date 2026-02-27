import json
import collections

def analyze_har(filename):
    print(f"\n--- Analyzing HAR: {filename} ---")
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return

    entries = har_data.get('log', {}).get('entries', [])
    print(f"Total Requests: {len(entries)}")

    # Analyze Requests
    domains = collections.Counter()
    auth_endpoints = []

    for entry in entries:
        req = entry.get('request', {})
        url = req.get('url', '')
        method = req.get('method', '')

        # Domain extraction
        try:
            domain = url.split('/')[2]
            domains[domain] += 1
        except:
            pass

        # Check for potential Auth/Login endpoints
        if "login" in url.lower() or "auth" in url.lower() or "token" in url.lower() or "account" in url.lower():
            auth_endpoints.append((method, url))

    print("\nTop 5 Domains Contacted:")
    for d, c in domains.most_common(5):
        print(f"{d}: {c}")

    print("\nPotential Auth/Login Endpoints:")
    for m, u in auth_endpoints[:10]:
        print(f"{m} {u[:100]}...") # Truncate long URLs

analyze_har("external_repo/login-dari-awal-bagian-1.har")
analyze_har("external_repo/login-dari-awal-bagian-2.har")
