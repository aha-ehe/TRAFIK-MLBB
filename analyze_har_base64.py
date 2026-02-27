import json
import base64
import re

def analyze_har_base64(file_path):
    print(f"Decoding base64 in {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Extract base64 encoded text: "text": "..." and "encoding": "base64"
    # This is tricky with regex because "encoding" might come before or after "text" in the JSON object.
    # However, usually the pattern in HAR is:
    # "content": { "size": ..., "mimeType": ..., "text": "BASE64...", "encoding": "base64" }

    # We will look for objects that contain "encoding": "base64" and extract the "text" field.

    # Let's split by "response" objects roughly
    responses = content.split('"response":')
    print(f"Found {len(responses)} response-like blocks.")

    decoded_snippets = []

    for resp in responses[1:]: # Skip the first split which is before the first response
        if '"encoding":"base64"' in resp or '"encoding": "base64"' in resp:
            # Try to find the text field
            match = re.search(r'"text"\s*:\s*"(.*?)"', resp)
            if match:
                b64_data = match.group(1)
                try:
                    decoded = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
                    # Search for keywords in decoded text
                    for keyword in ["ip", "port", "address", "server", "battle", "udp", "tcp", "game", "room"]:
                        if keyword in decoded.lower():
                             idx = decoded.lower().find(keyword)
                             start = max(0, idx - 50)
                             end = min(len(decoded), idx + 100)
                             decoded_snippets.append(f"[DECODED] {keyword}: ...{decoded[start:end]}...")
                except:
                    pass

    print(f"Found {len(decoded_snippets)} interesting snippets in decoded base64.")
    for snippet in decoded_snippets[:20]:
        print(snippet)

if __name__ == "__main__":
    analyze_har_base64('login-dari-awal-bagian-1.har')
    print("-" * 30)
    analyze_har_base64('login-dari-awal-bagian-2.har')
